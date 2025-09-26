import React, { useState } from 'react';
import axios from 'axios';
import GoogleSignIn from './GoogleSignIn';
import ContactSelector from './ContactSelector';

const API_URL = 'http://localhost:5000/api'; // Ensure this points to your backend

const FileUploader = () => {
    const [file, setFile] = useState(null);
    const [password, setPassword] = useState('');
    const [uploadData, setUploadData] = useState(null); // Stores file_id, download_link
    const [message, setMessage] = useState('');
    const [loading, setLoading] = useState(false);
    const [progress, setProgress] = useState(0); // For upload progress bar
    const [googleAccessToken, setGoogleAccessToken] = useState(null);

    // States for direct sharing inputs and their status
    const [directPhoneNumber, setDirectPhoneNumber] = useState('');
    const [directEmail, setDirectEmail] = useState('');
    const [directShareStatus, setDirectShareStatus] = useState('');

    const handleFileChange = (e) => {
        setFile(e.target.files[0]);
        setMessage('');
        setUploadData(null); // Reset previous upload data
        setProgress(0); // Reset progress
    };

    const handleUpload = async () => {
        if (!file) {
            alert('Please select a file first.');
            return;
        }

        setLoading(true);
        setMessage('Uploading file...');
        setProgress(0);
        const formData = new FormData();
        formData.append('file', file);
        if (password) {
            formData.append('password', password);
        }

        try {
            const response = await axios.post(`${API_URL}/upload`, formData, {
                headers: { 'Content-Type': 'multipart/form-data' },
                onUploadProgress: (progressEvent) => {
                    const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
                    setProgress(percentCompleted);
                },
            });
            setUploadData(response.data);
            setMessage('File uploaded successfully! Scanning for malware...');
            // Display malware scan status from backend response
            if (response.data.scan_status === 'clean') {
                setMessage('File uploaded and is clean! Ready to share.');
            } else if (response.data.scan_status === 'malicious') {
                setMessage('File uploaded but flagged as malicious! Not safe to share.');
            } else if (response.data.scan_status === 'failed') {
                setMessage('File upload complete, but malware scan failed. Proceed with caution.');
            } else {
                setMessage('File uploaded and ready to share.'); // Default if status is 'pending' or unexpected
            }
        } catch (error) {
            console.error('Upload failed:', error);
            setMessage(error.response?.data?.error || 'Upload failed: Could not upload file.');
            setUploadData(null); // Clear upload data on failure
        } finally {
            setLoading(false);
        }
    };

    const resetState = () => {
        setFile(null);
        setPassword('');
        setUploadData(null);
        setMessage('');
        setLoading(false);
        setProgress(0);
        setGoogleAccessToken(null);
        setDirectPhoneNumber('');
        setDirectEmail('');
        setDirectShareStatus('');
        // Clear file input visually
        const fileInput = document.getElementById('file-input');
        if (fileInput) fileInput.value = null;
    };

    const handleLoginSuccess = (accessToken) => {
        setGoogleAccessToken(accessToken);
        setMessage('Successfully signed in with Google. You can now select a contact to share.');
    };

    const handleShareDirectSms = async () => {
        if (!directPhoneNumber || !uploadData?.file_id) {
            setDirectShareStatus('Please enter a phone number and ensure a file is uploaded.');
            return;
        }
        setDirectShareStatus('Sending SMS...');
        try {
            const response = await axios.post(`${API_URL}/send`, {
                to_number: directPhoneNumber,
                file_id: uploadData.file_id,
            });
            setDirectShareStatus(response.data.message);
        } catch (error) {
            console.error('Direct SMS failed:', error);
            setDirectShareStatus(error.response?.data?.error || 'Failed to send SMS.');
        }
    };

    const handleShareDirectEmail = async () => {
        if (!directEmail || !uploadData?.file_id) {
            setDirectShareStatus('Please enter an email address and ensure a file is uploaded.');
            return;
        }
        setDirectShareStatus('Sending Email...');
        try {
            const response = await axios.post(`${API_URL}/send_email`, {
                to_email: directEmail,
                file_id: uploadData.file_id,
            });
            setDirectShareStatus(response.data.message);
        } catch (error) {
            console.error('Direct Email failed:', error);
            setDirectShareStatus(error.response?.data?.error || 'Failed to send email.');
        }
    };

    return (
        <div className="container mt-5">
            <div className="card p-4 shadow-sm">
                <h1 className="text-center mb-4">Secure File Share</h1>

                {/* Section 1: Upload File */}
                {!uploadData && (
                    <div className="mb-4">
                        <h2>1. Select and Secure Your File</h2>
                        <div className="mb-3">
                            <label htmlFor="file-input" className="form-label">File</label>
                            <input type="file" id="file-input" className="form-control" onChange={handleFileChange} />
                        </div>
                        <div className="mb-3">
                            <label htmlFor="password-input" className="form-label">Password (Optional)</label>
                            <input
                                type="password"
                                id="password-input"
                                className="form-control"
                                placeholder="Add a password for extra security"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                            />
                        </div>
                        {loading && progress > 0 && ( // Show progress bar only when loading and progress started
                            <div className="progress mb-3">
                                <div className="progress-bar" role="progressbar" style={{ width: `${progress}%` }} aria-valuenow={progress} aria-valuemin="0" aria-valuemax="100">
                                    {progress}%
                                </div>
                            </div>
                        )}
                        <button onClick={handleUpload} className="btn btn-primary w-100" disabled={loading || !file}>
                            {loading && progress < 100 ? 'Uploading...' : (loading && progress === 100 ? 'Scanning...' : 'Upload & Scan File')}
                        </button>
                        {message && !loading && (
                            <div className={`alert mt-3 ${message.includes('success') || message.includes('clean') || message.includes('ready') ? 'alert-success' : 'alert-danger'}`}>
                                {message}
                            </div>
                        )}
                    </div>
                )}

                {/* Section 2: Share File (visible after upload) */}
                {uploadData && (
                    <div>
                        <h2>2. Share Your File</h2>
                        <div className="alert alert-success">
                            <strong>File Uploaded!</strong>
                            <p className="mb-0">Download Link: <code>{uploadData.download_link}</code></p>
                        </div>

                        <p className="mt-4 mb-3 fw-bold">Choose a sharing method:</p>

                        <div className="row g-3">
                            {/* Option 1: Direct SMS */}
                            <div className="col-md-6">
                                <div className="card h-100 p-3">
                                    <h5 className="card-title"><i className="bi bi-chat-text-fill me-2"></i>Send via SMS</h5>
                                    <div className="input-group">
                                        <input
                                            type="tel"
                                            className="form-control"
                                            placeholder="Mobile number (+91...)"
                                            value={directPhoneNumber}
                                            onChange={(e) => setDirectPhoneNumber(e.target.value)}
                                        />
                                        <button onClick={handleShareDirectSms} className="btn btn-outline-primary" disabled={loading || !uploadData}>Send</button>
                                    </div>
                                </div>
                            </div>

                            {/* Option 2: Direct Email */}
                            <div className="col-md-6">
                                <div className="card h-100 p-3">
                                    <h5 className="card-title"><i className="bi bi-envelope-fill me-2"></i>Send via Email</h5>
                                    <div className="input-group">
                                        <input
                                            type="email"
                                            className="form-control"
                                            placeholder="Email address"
                                            value={directEmail}
                                            onChange={(e) => setDirectEmail(e.target.value)}
                                        />
                                        <button onClick={handleShareDirectEmail} className="btn btn-outline-primary" disabled={loading || !uploadData}>Send</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        {directShareStatus && <div className="alert alert-info mt-3">{directShareStatus}</div>}

                        {/* Option 3: Google Contacts */}
                        <div className="mt-4 text-center">
                            <hr />
                            <p className="fw-bold">Or share using Google Contacts</p>
                            {!googleAccessToken ? (
                                <GoogleSignIn onLoginSuccess={handleLoginSuccess} />
                            ) : (
                                <ContactSelector
                                    accessToken={googleAccessToken}
                                    fileId={uploadData.file_id}
                                />
                            )}
                        </div>
                        
                        <button onClick={resetState} className="btn btn-secondary w-100 mt-4">
                            Share Another File
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
};

export default FileUploader;