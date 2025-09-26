import React from 'react';
import { Routes, Route } from 'react-router-dom';
import { GoogleOAuthProvider } from '@react-oauth/google';
import FileUploader from './components/FileUploader';
import DownloadPage from './components/DownloadPage';
import './index.css';

function App() {
  const googleClientId = process.env.REACT_APP_GOOGLE_CLIENT_ID;

  if (!googleClientId) {
    return (
      <div className="container mt-5">
        <div className="alert alert-danger">
          Error: Google Client ID is not configured. Please check your frontend/.env file.
        </div>
      </div>
    );
  }

  return (
    <GoogleOAuthProvider clientId={googleClientId}>
      <div className="container">
        <header className="text-center my-4">
          <h1>Secure File Transfer</h1>
          <p className="lead text-muted">Upload a file, get it scanned, and share the link securely.</p>
        </header>
        <main>
          <Routes>
            <Route path="/" element={<FileUploader />} />
            <Route path="/download/:fileId" element={<DownloadPage />} />
          </Routes>
        </main>
      </div>
    </GoogleOAuthProvider>
  );
}

export default App;

