import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

function AuthCallback() {
  const navigate = useNavigate();

  useEffect(() => {
    // The backend has already set the session cookie during the Google login.
    // For this specific frontend (the auth portal itself), we can rely on that session
    // instead of completing the token exchange. The token endpoint is for other, external apps.
    // By simply redirecting home, the App.js component will mount and fetch the user
    // using the existing session, resulting in a seamless login.
    navigate('/');
  }, [navigate]);

  // Render a loading indicator while the redirect happens.
  return <div>Loading...</div>;
}

export default AuthCallback;
