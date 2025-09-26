import React, { useState } from 'react';
import axios from 'axios';
import GoogleSignIn from './GoogleSignIn';
import ContactSelector from './ContactSelector';

// --- THIS IS THE CRITICAL FIX ---
// Use the Vercel environment variable, but fall back to localhost for local development
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

const FileUploader = () => {
    const [file, setFile] = useState(null);
    const [password, setPassword] = useState('');
    const [uploadData, setUploadData] = useState(null);
    const [message, setMessage] = useState('');
    const [loading, setLoading] = useState(false);
    const [progress, setProgress] = useState(0);
    const [googleAccessToken, setGoogleAccessToken] = useState(null);
    const [directPhoneNumber, setDirectPhoneNumber] = useState('');
    const [directEmail, setDirectEmail] = useState('');
    const [directShareStatus, setDirectShareStatus] = useState('');

    const handleFileChange = (e) => {
        setFile(e.target.files[0]);
        setMessage('');
        setUploadData(null);
    };

    const handleUpload = async () => {
        if (!file) {
            alert('Please select a file first.');
            return;
        }
        setLoading(true);
        setMessage('Uploading...');
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
            setMessage('File uploaded successfully!');
        } catch (error) {
            console.error('Upload failed:', error);
            setMessage(error.response?.data?.error || 'Could not upload file.');
            setUploadData(null);
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
        setGoogleAccessToken(null);
        setDirectPhoneNumber('');
        setDirectEmail('');
        setDirectShareStatus('');
        document.getElementById('file-input').value = null;
    };

    const handleLoginSuccess = (accessToken) => {
        setGoogleAccessToken(accessToken);
    };

    const handleShareDirectSms = async () => {
        if (!directPhoneNumber || !uploadData?.file_id) return;
        setDirectShareStatus('Sending SMS...');
        try {
            const response = await axios.post(`${API_URL}/send`, {
                to_number: directPhoneNumber,
                file_id: uploadData.file_id,
            });
            setDirectShareStatus(response.data.message);
        } catch (error) {
            setDirectShareStatus(error.response?.data?.error || 'Failed to send SMS.');
        }
    };

    const handleShareDirectEmail = async () => {
        if (!directEmail || !uploadData?.file_id) return;
        setDirectShareStatus('Sending Email...');
        try {
            const response = await axios.post(`${API_URL}/send_email`, {
                to_email: directEmail,
                file_id: uploadData.file_id,
            });
            setDirectShareStatus(response.data.message);
        } catch (error) {
            setDirectShareStatus(error.response?.data?.error || 'Failed to send email.');
        }
    };

    return (
        <div className="card p-4 shadow-sm">
            {!uploadData ? (
                <div>
                    <h2 className="text-center mb-4">1. Select and Secure Your File</h2>
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
                    {loading && (
                        <div className="progress mb-3">
                            <div className="progress-bar" role="progressbar" style={{ width: `${progress}%` }} aria-valuenow={progress} aria-valuemin="0" aria-valuemax="100">{progress}%</div>
                        </div>
                    )}
                    <button onClick={handleUpload} className="btn btn-primary w-100" disabled={loading || !file}>
                        {loading ? 'Uploading...' : 'Upload & Scan File'}
                    </button>
                    {message && !loading && <div className={`alert mt-3 ${message.includes('success') ? 'alert-success' : 'alert-danger'}`}>{message}</div>}
                </div>
            ) : (
                <div>
                    <h2 className="text-center mb-4">2. Share Your File</h2>
                    <div className="alert alert-success">
                        <strong>File Uploaded!</strong>
                        <p className="mb-0">Shareable Link: <code>{uploadData.download_link}</code></p>
                    </div>
                    <p className="mt-4 mb-3 fw-bold">Choose a sharing method:</p>
                    <div className="row g-3">
                        <div className="col-md-6">
                            <div className="card h-100 p-3">
                                <h5 className="card-title"><i className="bi bi-chat-text-fill me-2"></i>Send via SMS</h5>
                                <div className="input-group">
                                    <input
                                        type="tel"
                                        className="form-control"
                                        placeholder="Mobile number"
                                        value={directPhoneNumber}
                                        onChange={(e) => setDirectPhoneNumber(e.target.value)}
                                    />
                                    <button onClick={handleShareDirectSms} className="btn btn-outline-secondary">Send</button>
                                </div>
                            </div>
                        </div>
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
                                    <button onClick={handleShareDirectEmail} className="btn btn-outline-secondary">Send</button>
                                </div>
                            </div>
                        </div>
                    </div>
                    {directShareStatus && <div className="alert alert-info mt-3">{directShareStatus}</div>}
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
    );
};

export default FileUploader;

