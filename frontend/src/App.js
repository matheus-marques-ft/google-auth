import React, { useState, useEffect } from 'react';
import axios from 'axios';
import pkceChallenge from 'pkce-challenge';
import './App.css';
import logo from './images/fretecom.png'; // Import the logo

// Set up axios to send credentials with requests
axios.defaults.withCredentials = true;

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true); // Add loading state

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const response = await axios.get('http://localhost:5000/api/user');
        setUser(response.data);
      } catch (error) {
        console.log('Not authenticated');
        setUser(null); // Explicitly set user to null on error
      } finally {
        setLoading(false); // Set loading to false after the fetch attempt
      }
    };

    fetchUser();
  }, []);

  const login = () => {
    const challenge = pkceChallenge(128);
    const state = crypto.randomUUID(); // Generate a random state

    // Store the verifier and state in the session to retrieve later
    sessionStorage.setItem('code_verifier', challenge.code_verifier);
    sessionStorage.setItem('state', state);

    const authorizationUrl = new URL('http://localhost:5000/authorize');
    authorizationUrl.searchParams.append('client_id', 'auth-portal-client');
    authorizationUrl.searchParams.append('redirect_uri', 'http://localhost:3000/callback');
    authorizationUrl.searchParams.append('response_type', 'code');
    authorizationUrl.searchParams.append('scope', 'openid profile email'); // Standard OIDC scopes
    authorizationUrl.searchParams.append('state', state);
    authorizationUrl.searchParams.append('code_challenge', challenge.code_challenge);
    authorizationUrl.searchParams.append('code_challenge_method', 'S256');

    // Redirect to the backend's authorization endpoint
    window.location.href = authorizationUrl.toString();
  };

  const logout = async () => {
    try {
      await axios.get(`${process.env.REACT_APP_API_URL}/api/logout`);
      setUser(null);
      // After logout, the app will re-render and show the login button.
    } catch (error) {
      console.error('Error logging out', error);
    }
  };

  const handleCardClick = (subsystem) => {
    // In the future, this will redirect to the selected subsystem.
    alert(`Redirecting to ${subsystem}...`);
  };

  // While loading, render nothing (or a spinner)
  if (loading) {
    return null; // or <div className="App-loading">Loading...</div>;
  }

  return (
    <div className="App">
      {user ? (
        <>
          <div className="userInfo">
            <img src={user.photos[0].value} alt="Profile" className="profile-pic" />
            <span>Bem vindo, {user.displayName}</span>
            <button onClick={logout} className="logout-btn">
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
            </button>
          </div>
          <header className="App-header">
            <div className="container">
              <h2>Escolha a aplicação que deseja acessar:</h2>
              <div className="card-container">
                <div className="card" onClick={() => handleCardClick('Subsystem 1')}>
                  <h3>Matriz de Acessos</h3>
                  <p>Essa aplição é utilizada para centralizar os acessos, revisões e mapeamento de privilégios dos colaboradores frete.com.</p>
                </div>
                <div className="card" onClick={() => handleCardClick('Subsystem 2')}>
                  <h3>Forum de Cybersegurança</h3>
                  <p>Essa aplicação é um guia sobre as atividades do time de Cybersegurança.</p>
                </div>
                <div className="card" onClick={() => handleCardClick('Subsystem 3')}>
                  <h3>Painel de Cybersegurança</h3>
                  <p>Essa aplicação é um dashboard dos controles do time de Cybersegurança.</p>
                </div>
              </div>
            </div>
          </header>
        </>
      ) : (
        <header className="App-header">
          <div className="login-card">
            <img src={logo} alt="Frete.com Logo" className="company-logo" />
            <button onClick={login} className="btn">Entrar com Google</button>
          </div>
        </header>
      )}
    </div>
  );
}

export default App;
