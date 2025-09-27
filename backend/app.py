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
logging.basicConfig(level=logging.INFO)

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
CORS(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
twilio_client = Client(os.environ.get('TWILIO_ACCOUNT_SID'), os.environ.get('TWILIO_AUTH_TOKEN'))
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
    """This function runs in a background thread to avoid server timeouts."""
    with app_context:
        scan_status = 'pending'
        try:
            if not VIRUSTOTAL_API_KEY:
                scan_status = 'skipped'
            else:
                with open(temp_filepath, 'rb') as f:
                    files = {'file': (os.path.basename(temp_filepath), f)}
                    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
                    response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files, timeout=60)
                    response.raise_for_status()
                    analysis_id = response.json()['data']['id']
                    
                    for _ in range(15): # Poll for up to 2.5 minutes
                        time.sleep(10)
                        analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=30)
                        analysis_response.raise_for_status()
                        report = analysis_response.json()
                        status = report['data']['attributes']['status']
                        if status == 'completed':
                            results = report['data']['attributes']
                            stats = results.get('stats', results.get('last_analysis_stats', {}))
                            if stats.get('malicious', 0) > 0:
                                scan_status = 'malicious'
                            else:
                                scan_status = 'clean'
                            break 
        except Exception as e:
            logging.error(f"Background scan for {file_id} failed: {e}")
            scan_status = 'failed'
        finally:
            # Update the database with the final scan status
            file_record = File.query.filter_by(file_id=file_id).first()
            if file_record:
                file_record.scan_status = scan_status
                db.session.commit()
            
            # If the file was found to be malicious, delete it from S3
            if scan_status == 'malicious' and file_record:
                try:
                    s3_client.delete_object(Bucket=S3_BUCKET, Key=file_record.s3_key)
                    logging.warning(f"Deleted malicious file {file_record.s3_key} from S3.")
                except Exception as e:
                    logging.error(f"Failed to delete malicious S3 object {file_record.s3_key}: {e}")

            # Clean up the local temporary file from the server
            if os.path.exists(temp_filepath):
                os.remove(temp_filepath)

# --- API Routes ---
@api.route('/upload', methods=['POST'])
def upload_file_endpoint():
    if 'file' not in request.files: return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({"error": "No selected file"}), 400

    file_id = generate_unique_file_id()
    s3_key = f"uploads/{file_id}/{file.filename}"
    temp_filepath = os.path.join(UPLOAD_FOLDER, file_id)

    try:
        # 1. Save the file to a temporary local path
        file.save(temp_filepath)
        
        # 2. Upload the file to S3 immediately
        with open(temp_filepath, "rb") as f:
            s3_client.upload_fileobj(f, S3_BUCKET, s3_key)

        # 3. Save the file's metadata to the database with a 'pending' scan status
        password = request.form.get('password')
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8') if password else None
        
        new_file = File(
            file_id=file_id, filename=file.filename, s3_key=s3_key,
            password_hash=password_hash, expiry_date=datetime.utcnow() + timedelta(hours=24),
            scan_status='pending'
        )
        db.session.add(new_file)
        db.session.commit()
        
        # 4. Start the long-running scan in a background thread
        scan_thread = threading.Thread(
            target=scan_file_and_update_db,
            args=(app.app_context(), file_id, temp_filepath)
        )
        scan_thread.start()

        # 5. Respond to the user immediately, without waiting for the scan
        download_link = f"{FRONTEND_BASE_URL}/download/{file_id}"
        return jsonify({
            "message": "File upload successful! Scanning in the background.",
            "file_id": file_id,
            "download_link": download_link,
            "scan_status": "pending"
        }), 200

    except Exception as e:
        db.session.rollback()
        if os.path.exists(temp_filepath): os.remove(temp_filepath)
        logging.error(f"File upload process failed: {e}", exc_info=True)
        return jsonify({"error": "Could not upload file due to an internal server error."}), 500

@api.route('/download/<file_id>', methods=['GET'])
def download_file_info(file_id):
    file_record = File.query.filter_by(file_id=file_id).first_or_404()
    if file_record.expiry_date < datetime.utcnow():
        return jsonify({"error": "File has expired."}), 410
    return jsonify({
        "file_id": file_record.file_id, "filename": file_record.filename,
        "requires_password": file_record.password_hash is not None,
        "scan_status": file_record.scan_status
    })

@api.route('/download/<file_id>/request_url', methods=['POST'])
def request_download_url(file_id):
    file_record = File.query.filter_by(file_id=file_id).first_or_404()
    if file_record.expiry_date < datetime.utcnow():
        return jsonify({"error": "File has expired."}), 410
    
    if file_record.password_hash:
        password = request.json.get('password')
        if not password or not bcrypt.check_password_hash(file_record.password_hash, password):
            return jsonify({"error": "Invalid password."}), 401

    try:
        url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': S3_BUCKET, 'Key': file_record.s3_key, 'ResponseContentDisposition': f'attachment; filename="{file_record.filename}"'},
            ExpiresIn=300
        )
        return jsonify({"download_url": url})
    except ClientError as e:
        logging.error(f"S3 presigned URL generation failed: {e}")
        return jsonify({"error": "Could not generate download link."}), 500

@api.route('/send', methods=['POST'])
def send_sms_endpoint():
    data = request.get_json()
    to_number, file_id = data.get('to_number'), data.get('file_id')
    if not to_number or not file_id: return jsonify({"error": "Missing recipient number or file ID."}), 400
    
    formatted_number = str(to_number).strip()
    if not formatted_number.startswith('+') and len(formatted_number) == 10 and formatted_number.isdigit():
        formatted_number = f"+91{formatted_number}"

    download_link = f"{FRONTEND_BASE_URL}/download/{file_id}"
    message_body = f"You have received a secure file. Use this link to download: {download_link}. It expires in 24 hours."
    
    try:
        twilio_client.messages.create(
            to=formatted_number,
            from_=os.environ.get('TWILIO_PHONE_NUMBER'),
            body=message_body
        )
        return jsonify({"message": f"SMS sent successfully to {formatted_number}."})
    except Exception as e:
        logging.error(f"Twilio SMS failed: {e}", exc_info=True)
        return jsonify({"error": "Failed to send SMS. Please ensure the number is valid and verified in your Twilio trial account."}), 500

@api.route('/send_email', methods=['POST'])
def send_email_endpoint():
    data = request.get_json()
    to_email, file_id = data.get('to_email'), data.get('file_id')
    if not to_email or not file_id: return jsonify({"error": "Missing recipient email or file ID."}), 400
    
    download_link = f"{FRONTEND_BASE_URL}/download/{file_id}"
    
    try:
        msg = Message(
            "You have received a secure file",
            sender=("Secure File Share", app.config['MAIL_USERNAME']),
            recipients=[to_email]
        )
        msg.body = f"You have received a secure file. Please use the following link to download it:\n\n{download_link}\n\nThe link will expire in 24 hours."
        mail.send(msg)
        return jsonify({"message": f"Email sent successfully to {to_email}."})
    except Exception as e:
        logging.error(f"Mail sending failed: {e}", exc_info=True)
        return jsonify({"error": "Failed to send email."}), 500

# [ The Google Contacts routes would go here if you add them back ]

# --- Register the Blueprint ---
app.register_blueprint(api)

# --- Flask CLI Commands ---
@app.cli.command("init-db")
def init_db_command():
    with app.app_context():
        db.drop_all()
        db.create_all()
    print("Initialized the database with the S3 schema.")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

    

