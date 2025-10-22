import os
import secrets
import logging
import time
from datetime import datetime, timedelta
import threading

import requests
import boto3
from botocore.exceptions import ClientError
from flask import Flask, request, jsonify, Blueprint, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from twilio.rest import Client
from flask_mail import Mail, Message
from dotenv import load_dotenv

# --- Initialization & Configuration ---
load_dotenv()
app = Flask(__name__)
logging.basicConfig(level=logging.INFO) # Keep logging level at INFO

# --- Configurations from .env ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
db_url = os.environ.get('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() in ['true', 'on', '1']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

# --- Extensions & Clients ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
CORS(app) # Enable CORS for all routes
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
# Initialize Twilio client using environment variables
twilio_client = Client(os.environ.get('TWILIO_ACCOUNT_SID'), os.environ.get('TWILIO_AUTH_TOKEN'))
# Initialize S3 client using environment variables
s3_client = boto3.client(
    "s3",
    aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
    region_name=os.environ.get("AWS_S3_REGION")
)
S3_BUCKET = os.environ.get("AWS_S3_BUCKET_NAME")
FRONTEND_BASE_URL = os.environ.get('BASE_URL')
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- Database Model (for S3) ---
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.String(32), unique=True, nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    s3_key = db.Column(db.String(500), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    scan_status = db.Column(db.String(50), default='pending')

# --- API Blueprint ---
api = Blueprint('api', __name__, url_prefix='/api')

# --- Helper Functions ---
def generate_unique_file_id():
    return secrets.token_urlsafe(24)

def scan_file_and_update_db(app_context, file_id, temp_filepath):
    """Runs VirusTotal scan in background, updates DB, deletes malicious S3 objects."""
    with app_context:
        scan_status = 'pending'
        try:
            if not VIRUSTOTAL_API_KEY:
                scan_status = 'skipped'
                logging.warning(f"VirusTotal key missing, scan skipped for {file_id}.")
            else:
                with open(temp_filepath, 'rb') as f:
                    files = {'file': (os.path.basename(temp_filepath), f)}
                    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
                    # Upload for analysis
                    response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files, timeout=60)
                    response.raise_for_status()
                    analysis_id = response.json()['data']['id']
                    logging.info(f"VT Scan initiated for {file_id} (Analysis ID: {analysis_id})")

                    # Poll for results
                    for _ in range(15): # Poll for up to 150 seconds (2.5 minutes)
                        time.sleep(10)
                        analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=30)
                        analysis_response.raise_for_status()
                        report = analysis_response.json()
                        current_status = report['data']['attributes']['status']
                        if current_status == 'completed':
                            results = report['data']['attributes']
                            # Check both 'stats' (for new scans) and 'last_analysis_stats' (for rescans)
                            stats = results.get('stats', results.get('last_analysis_stats', {}))
                            if stats.get('malicious', 0) > 0:
                                scan_status = 'malicious'
                                logging.warning(f"VT Scan result for {file_id}: MALICIOUS")
                            else:
                                scan_status = 'clean'
                                logging.info(f"VT Scan result for {file_id}: CLEAN")
                            break # Exit loop once completed
                        elif current_status in ['queued', 'inprogress']:
                            logging.info(f"VT Scan for {file_id} still '{current_status}'...")
                        else:
                            scan_status = 'failed'
                            logging.error(f"VT Scan for {file_id} failed with status: {current_status}")
                            break # Exit loop on unexpected status
                    else: # Loop finished without completing
                        scan_status = 'pending' # Or potentially 'timeout'
                        logging.warning(f"VT Scan for {file_id} timed out after polling.")

        except requests.exceptions.RequestException as e:
            logging.error(f"VT API request error during scan for {file_id}: {e}")
            scan_status = 'failed'
        except Exception as e:
            logging.error(f"Unexpected error during background scan for {file_id}: {e}", exc_info=True)
            scan_status = 'failed'
        finally:
            # Update the database record
            file_record = File.query.filter_by(file_id=file_id).first()
            if file_record:
                file_record.scan_status = scan_status
                try:
                    db.session.commit()
                    logging.info(f"DB updated for {file_id} with scan status: {scan_status}")
                except Exception as db_err:
                    db.session.rollback()
                    logging.error(f"Failed to update DB for {file_id} after scan: {db_err}")

                # If malicious, attempt to delete from S3
                if scan_status == 'malicious':
                    try:
                        s3_client.delete_object(Bucket=S3_BUCKET, Key=file_record.s3_key)
                        logging.warning(f"Deleted malicious S3 object {file_record.s3_key}.")
                    except Exception as s3_err:
                        logging.error(f"Failed to delete malicious S3 object {file_record.s3_key}: {s3_err}")

            # Always clean up the local temporary file
            if os.path.exists(temp_filepath):
                try:
                    os.remove(temp_filepath)
                except Exception as rm_err:
                     logging.error(f"Failed to remove temp file {temp_filepath}: {rm_err}")

def send_email_in_background(app_context, subject, sender, recipients, body):
    """Sends email asynchronously in a background thread."""
    with app_context:
        try:
            msg = Message(subject=subject, sender=sender, recipients=recipients, body=body)
            mail.send(msg)
            logging.info(f"Background email successfully sent to {recipients[0]}")
        except Exception as e:
            logging.error(f"Background email sending to {recipients[0]} failed: {e}", exc_info=True)

# --- API Routes ---
@api.route('/upload', methods=['POST'])
@limiter.limit("5 per minute") # Limit upload attempts
def upload_file_endpoint():
    if 'file' not in request.files: return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({"error": "No selected file"}), 400

    file_id = generate_unique_file_id()
    # Sanitize filename for S3 key - replace spaces and potentially unsafe chars
    safe_filename = "".join(c if c.isalnum() or c in ['.', '-', '_'] else '_' for c in file.filename)
    s3_key = f"uploads/{file_id}/{safe_filename}"
    temp_filepath = os.path.join(UPLOAD_FOLDER, file_id) # Use unique ID for temp file too

    try:
        # 1. Save locally temporarily
        file.save(temp_filepath)
        
        # 2. Upload to S3 immediately
        logging.info(f"Uploading {file.filename} to S3 bucket {S3_BUCKET} with key {s3_key}")
        with open(temp_filepath, "rb") as f:
            s3_client.upload_fileobj(f, S3_BUCKET, s3_key)
        logging.info(f"Successfully uploaded {file.filename} to S3.")

        # 3. Save metadata to DB with 'pending' status
        password = request.form.get('password')
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8') if password else None
        
        new_file = File(
            file_id=file_id, filename=file.filename, s3_key=s3_key,
            password_hash=password_hash, expiry_date=datetime.utcnow() + timedelta(hours=24),
            scan_status='pending'
        )
        db.session.add(new_file)
        db.session.commit()
        logging.info(f"Saved metadata to DB for file_id: {file_id}")
        
        # 4. Start the long-running scan in a background thread
        scan_thread = threading.Thread(
            target=scan_file_and_update_db,
            args=(app.app_context(), file_id, temp_filepath) # Pass app_context for DB access in thread
        )
        scan_thread.start()
        logging.info(f"Started background scan thread for file_id: {file_id}")

        # 5. Respond to the user immediately
        download_link = f"{FRONTEND_BASE_URL}/download/{file_id}"
        return jsonify({
            "message": "File upload successful! Scanning in the background.",
            "file_id": file_id,
            "download_link": download_link,
            "scan_status": "pending" # Initial status
        }), 200

    except ClientError as e:
        logging.error(f"S3 Upload failed: {e}", exc_info=True)
        # Attempt cleanup even on S3 error
        if os.path.exists(temp_filepath): os.remove(temp_filepath)
        return jsonify({"error": "Could not upload file to cloud storage."}), 500
    except Exception as e:
        db.session.rollback()
        if os.path.exists(temp_filepath): os.remove(temp_filepath)
        logging.error(f"File upload process failed: {e}", exc_info=True)
        return jsonify({"error": "Could not upload file due to an internal server error."}), 500

@api.route('/download/<file_id>', methods=['GET'])
@limiter.limit("20 per minute")
def download_file_info(file_id):
    """Provides metadata about the file before download."""
    file_record = File.query.filter_by(file_id=file_id).first()
    if not file_record:
        return jsonify({"error": "File not found."}), 404

    if file_record.expiry_date < datetime.utcnow():
        # Clean up expired file record (S3 object cleanup might need a separate job)
        db.session.delete(file_record)
        db.session.commit()
        return jsonify({"error": "File has expired."}), 410 # Gone

    return jsonify({
        "file_id": file_record.file_id,
        "filename": file_record.filename,
        "requires_password": file_record.password_hash is not None,
        "scan_status": file_record.scan_status # Let frontend know the scan status
    })

@api.route('/download/<file_id>/request_url', methods=['POST'])
@limiter.limit("10 per minute")
def request_download_url(file_id):
    """Generates a secure, temporary S3 presigned URL for download."""
    file_record = File.query.filter_by(file_id=file_id).first()
    if not file_record:
        return jsonify({"error": "File not found."}), 404

    if file_record.expiry_date < datetime.utcnow():
        db.session.delete(file_record)
        db.session.commit()
        return jsonify({"error": "File has expired."}), 410

    # Optional: Prevent download if scan isn't clean
    # if file_record.scan_status not in ['clean', 'skipped', 'pending']:
    #    return jsonify({"error": f"Download blocked: File scan status is '{file_record.scan_status}'."}), 403

    if file_record.password_hash:
        password = request.json.get('password')
        if not password or not bcrypt.check_password_hash(file_record.password_hash, password):
            return jsonify({"error": "Invalid password."}), 401

    try:
        # Generate a presigned URL valid for 5 minutes (300 seconds)
        # Include ResponseContentDisposition to suggest original filename to browser
        url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': S3_BUCKET,
                'Key': file_record.s3_key,
                'ResponseContentDisposition': f'attachment; filename="{file_record.filename}"'
            },
            ExpiresIn=300
        )
        logging.info(f"Generated presigned URL for file_id: {file_id}")
        return jsonify({"download_url": url})
    except ClientError as e:
        logging.error(f"S3 presigned URL generation failed for {file_id}: {e}")
        return jsonify({"error": "Could not generate download link."}), 500
    except Exception as e:
        logging.error(f"Unexpected error during presigned URL generation for {file_id}: {e}", exc_info=True)
        return jsonify({"error": "Could not generate download link due to server error."}), 500


@api.route('/send', methods=['POST'])
@limiter.limit("10 per minute")
def send_sms_endpoint():
    """Sends SMS with download link, auto-formatting number."""
    data = request.get_json()
    to_number, file_id = data.get('to_number'), data.get('file_id')
    if not to_number or not file_id: return jsonify({"error": "Missing recipient number or file ID."}), 400
    
    formatted_number = str(to_number).strip()
    # Simple check for Indian numbers - adjust if needed for other countries
    if not formatted_number.startswith('+') and len(formatted_number) == 10 and formatted_number.isdigit():
        formatted_number = f"+91{formatted_number}"

    download_link = f"{FRONTEND_BASE_URL}/download/{file_id}"
    message_body = f"You received a secure file. Download link (expires in 24 hrs): {download_link}"
    
    try:
        twilio_phone_number = os.environ.get('TWILIO_PHONE_NUMBER')
        if not twilio_phone_number:
             logging.error("Twilio phone number not configured.")
             return jsonify({"error": "SMS service not configured on server."}), 500

        message = twilio_client.messages.create(
            to=formatted_number,
            from_=twilio_phone_number,
            body=message_body
        )
        logging.info(f"SMS sent successfully to {formatted_number} via Twilio SID: {message.sid}")
        return jsonify({"message": f"SMS sent successfully to {formatted_number}."})
    except Exception as e:
        # Log the detailed Twilio error if available
        error_message = str(e)
        logging.error(f"Twilio SMS failed to {formatted_number}: {error_message}", exc_info=True)
        # Provide a slightly more informative error to the frontend if possible
        user_error = "Failed to send SMS."
        if "Invalid 'To' Phone Number" in error_message:
            user_error = "Failed to send SMS: Invalid phone number format."
        elif "Authenticate" in error_message:
             user_error = "Failed to send SMS: Authentication error (check server config)."
        elif "permission to send" in error_message: # Trial account restriction
             user_error = "Failed to send SMS. Trial accounts can only send to verified numbers."

        return jsonify({"error": user_error}), 500

@api.route('/send_email', methods=['POST'])
@limiter.limit("10 per minute")
def send_email_endpoint():
    """Initiates background email sending."""
    data = request.get_json()
    to_email, file_id = data.get('to_email'), data.get('file_id')
    if not to_email or not file_id: return jsonify({"error": "Missing recipient email or file ID."}), 400
    
    # Check if mail is configured before starting thread
    sender_email = app.config.get('MAIL_USERNAME')
    if not sender_email or not app.config.get('MAIL_PASSWORD'):
        logging.error("Email server (MAIL_USERNAME/MAIL_PASSWORD) not configured.")
        return jsonify({"error": "Email service not configured on server."}), 500

    download_link = f"{FRONTEND_BASE_URL}/download/{file_id}"
    subject = "You have received a secure file"
    sender_tuple = ("Secure File Share", sender_email)
    recipients = [to_email]
    body = f"You have received a secure file. Please use the following link to download it:\n\n{download_link}\n\nThe link will expire in 24 hours."
    
    # Start sending the email in a background thread
    email_thread = threading.Thread(
        target=send_email_in_background,
        args=(app.app_context(), subject, sender_tuple, recipients, body)
    )
    email_thread.start()
    logging.info(f"Background email sending initiated to {to_email} for file {file_id}.")

    # Respond immediately
    return jsonify({"message": f"Email sending to {to_email} has been initiated."})

# --- Register the Blueprint ---
app.register_blueprint(api)

# --- Flask CLI Commands ---
@app.cli.command("init-db")
def init_db_command():
    """Initializes/Re-creates the database tables."""
    with app.app_context():
        # db.drop_all() # Use drop_all cautiously, especially in production environments
        db.create_all()
    print("Initialized the database tables.")

if __name__ == '__main__':
    # Use Flask's built-in server for local development (debug=True enables auto-reload)
    # app.run(host='0.0.0.0', port=5000, debug=True)
    # For Render/production, gunicorn will run the app, so this block isn't executed there.
    # The 'flask run --host=0.0.0.0' command uses this block if run directly.
     app.run(host='0.0.0.0', port=5000)

