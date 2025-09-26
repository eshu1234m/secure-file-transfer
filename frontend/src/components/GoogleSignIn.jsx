import React from 'react';
import { useGoogleLogin } from '@react-oauth/google';

function GoogleSignIn({ onLoginSuccess }) {
  const login = useGoogleLogin({
    onSuccess: (tokenResponse) => {
      onLoginSuccess(tokenResponse.access_token);
    },
    onError: () => {
      console.error('Google Login Failed');
      alert('Login Failed. Please try again.');
    },
    // Request permission to read the user's contacts
    scope: 'https://www.googleapis.com/auth/contacts.readonly',
  });

  return (
    <div>
      <button onClick={() => login()} className="btn btn-primary w-100">
        <i className="bi bi-google me-2"></i> Sign in with Google
      </button>
    </div>
  );
}

export default GoogleSignIn;