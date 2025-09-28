import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useParams } from 'react-router-dom';

// --- THIS IS THE CRITICAL FIX ---
// Use the Vercel environment variable, but fall back to localhost for local development
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

const DownloadPage = () => {
    const { fileId } = useParams(); // Get fileId from the URL (e.g., /download/xyz)
    const [fileInfo, setFileInfo] = useState(null);
    const [password, setPassword] = useState('');
    const [message, setMessage] = useState('Fetching file details...');
    const [error, setError] = useState('');

    useEffect(() => {
        if (fileId) {
            axios.get(`${API_URL}/download/${fileId}`)
                .then(res => {
                    setFileInfo(res.data);
                    setMessage('');
                })
                .catch(err => {
                    setError(err.response?.data?.error || 'File not found or has expired.');
                    setMessage('');
                });
        }
    }, [fileId]);

    const handleDownload = async () => {
        if (!fileInfo) return;

        setMessage('Generating secure link...');
        setError('');
        try {
            const response = await axios.post(`${API_URL}/download/${fileId}/request_url`, { password });
            // This will redirect the browser to the temporary S3 link, starting the download
            window.location.href = response.data.download_url;
        } catch (err) {
            setError(err.response?.data?.error || 'Could not start download. Please check the password.');
            setMessage('');
        }
    };

    if (error) {
        return (
            <div className="container mt-5">
                <div className="alert alert-danger">
                    <h4>Error</h4>
                    <p>{error}</p>
                    <a href="/" className="btn btn-primary">Go to Homepage</a>
                </div>
            </div>
        );
    }

    if (!fileInfo) {
        return <div className="container mt-5"><p>{message}</p></div>;
    }

    return (
        <div className="container mt-5">
            <div className="card p-4 shadow-sm">
                <h2 className="text-center mb-4">Download File</h2>
                <div className="alert alert-info">
                    <p className="mb-1"><strong>Filename:</strong> {fileInfo.filename}</p>
                </div>
                
                {fileInfo.requires_password && (
                    <div className="mb-3">
                        <label htmlFor="password-input" className="form-label fw-bold">Password Required</label>
                        <input
                            type="password"
                            id="password-input"
                            className="form-control"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="Enter the download password"
                        />
                    </div>
                )}
                
                <button className="btn btn-primary w-100" onClick={handleDownload}>
                    Download Now
                </button>
                {message && <p className="text-center mt-3">{message}</p>}
            </div>
        </div>
    );
};

export default DownloadPage;

