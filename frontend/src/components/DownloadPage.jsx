import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useParams, useNavigate } from 'react-router-dom';

const API_URL = 'http://localhost:5000/api';

const DownloadPage = () => {
    const { fileId } = useParams(); // Get fileId from the URL, e.g., "some-unique-id"
    const navigate = useNavigate(); // Hook to allow programmatic navigation
    const [fileInfo, setFileInfo] = useState(null);
    const [password, setPassword] = useState('');
    const [message, setMessage] = useState('Fetching file details...');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    useEffect(() => {
        // Fetch file metadata when the page first loads
        axios.get(`${API_URL}/download/${fileId}`)
            .then(res => {
                setFileInfo(res.data);
                setMessage('');
            })
            .catch(err => {
                setError(err.response?.data?.error || 'File not found or the link has expired.');
                setMessage('');
            });
    }, [fileId]);

    const handleDownload = async () => {
        setIsLoading(true);
        setMessage('Generating secure download link...');
        setError('');
        try {
            // Step 1: Request the secure S3 URL from the backend, sending the password if needed
            const response = await axios.post(`${API_URL}/download/${fileId}/request_url`, { password });
            
            // Step 2: Redirect the browser to the secure S3 link to start the download
            window.location.href = response.data.download_url;
            setMessage('Your download will begin shortly...');

        } catch (err) {
            setError(err.response?.data?.error || 'Could not start download. Please check the password and try again.');
            setMessage('');
        } finally {
            setIsLoading(false);
        }
    };

    if (error) {
        return (
            <div className="container mt-5">
                <div className="card p-4 text-center">
                    <div className="alert alert-danger">{error}</div>
                    <button onClick={() => navigate('/')} className="btn btn-primary mt-2">
                        Go to Homepage
                    </button>
                </div>
            </div>
        );
    }

    if (!fileInfo) {
        return <div className="container mt-5"><p className="text-center">{message}</p></div>;
    }

    return (
        <div className="container mt-5">
            <div className="card p-4 shadow-sm">
                <h2 className="text-center mb-4">Download File</h2>
                <div className="alert alert-info">
                    <p className="mb-1"><strong>Filename:</strong> {fileInfo.filename}</p>
                    <p className="mb-0"><strong>Expires:</strong> {new Date(fileInfo.expiry_date).toLocaleString()}</p>
                </div>
                
                {fileInfo.requires_password && (
                    <div className="mb-3">
                        <label htmlFor="password-input" className="form-label">Password Required</label>
                        <input
                            type="password"
                            id="password-input"
                            className="form-control"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="Enter download password"
                        />
                    </div>
                )}
                
                <button className="btn btn-primary w-100" onClick={handleDownload} disabled={isLoading}>
                    {isLoading ? 'Preparing Download...' : 'Download Now'}
                </button>

                {message && !error && <p className="mt-3 text-center text-muted">{message}</p>}
            </div>
        </div>
    );
};

export default DownloadPage;

