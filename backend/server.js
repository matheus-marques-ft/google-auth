require('dotenv').config(); // Load environment variables from .env file

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cors = require('cors');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

const app = express();

// --- CONFIGURAÇÕES ---
const JWT_SECRET = 'CHAVE_SECRETA_SUPER_FORTE_PARA_ASSINATURA_DE_TOKENS';

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors({
    origin: process.env.CORS_ORIGIN, // Allow the React app to make requests
    credentials: true
}));
app.use(session({
    secret: process.env.SESSION_SECRET, // Use the session secret from .env
    resave: false,
    saveUninitialized: true,
    cookie: {
        sameSite: 'lax' // Prevent session loss on OAuth redirect
    }
}));
app.use(passport.initialize());
app.use(passport.session());

// Passport configuration
passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
  },
  (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
  }
));

// In-memory store for authorization codes and clients
const authorizationCodes = {};
const CLIENT_REDIRECT_URIS = {
    'matriz-acessos-client-id': 'http://localhost:5173/auth/callback',
    'auth-portal-client': 'http://localhost:3000/callback'
};

// --- OIDC/OAuth2 Logic ---

/**
 * Issues an authorization code and redirects to the client's callback URI.
 * This is the final step of the authorization flow.
 */
function issueCodeAndRedirect(req, res) {
  // req.authorization is expected to be populated by the calling route
  if (!req.authorization) {
      const errorRedirect = new URL(process.env.CORS_ORIGIN || 'http://localhost:3000');
      errorRedirect.searchParams.append('error', 'authorization_session_expired');
      errorRedirect.searchParams.append('error_description', 'Sua sessão de autorização expirou. Por favor, tente o login novamente.');
      return res.redirect(errorRedirect.toString());
  }

  const { client_id, redirect_uri, state } = req.authorization;
  const code = crypto.randomBytes(32).toString('hex');

  authorizationCodes[code] = {
      user: req.user,
      code_challenge: req.authorization.code_challenge,
      code_challenge_method: req.authorization.code_challenge_method,
      client_id,
      expires: Date.now() + 10 * 60 * 1000 // 10 minutes
  };

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.append('code', code);
  redirectUrl.searchParams.append('state', state);

  res.redirect(redirectUrl.toString());
}

// 1. Authorization Endpoint
app.get('/authorize', (req, res) => {
    const { client_id, redirect_uri, state, code_challenge, code_challenge_method, scope } = req.query;

    if (!client_id || !redirect_uri || !state || !code_challenge) {
        return res.status(400).send('Parâmetros de autorização inválidos.');
    }

    if (CLIENT_REDIRECT_URIS[client_id] !== redirect_uri) {
        return res.status(400).send('Client ID ou Redirect URI inválido.');
    }

    req.session.authorization = {
        client_id,
        redirect_uri,
        state,
        code_challenge,
        code_challenge_method,
        scope
    };

    req.session.save((err) => {
        if (err) {
            console.error('Failed to save session before redirect:', err);
            return res.status(500).send('Ocorreu um erro ao processar sua autenticação.');
        }

        if (!req.isAuthenticated()) {
            // If user is not logged in to the auth server, send them to Google
            res.redirect('/auth/google');
        } else {
            // If user is already logged in (SSO), issue the code directly
            req.authorization = req.session.authorization;
            issueCodeAndRedirect(req, res);
        }
    });
});

// 2. Google Authentication routes
app.get('/auth/google', (req, res, next) => {
  const scope = (req.session.authorization && req.session.authorization.scope)
    ? req.session.authorization.scope.split(' ')
    : ['profile', 'email'];
  
  passport.authenticate('google', { scope })(req, res, next);
});

app.get('/auth/google/callback',
  (req, res, next) => {
    // Move authorization data from session to req to survive session regeneration
    if (req.session.authorization) {
      req.authorization = req.session.authorization;
    }
    next();
  },
  passport.authenticate('google', { failureRedirect: `${process.env.CORS_ORIGIN || 'http://localhost:3000'}?error=google_auth_failed` }),
  issueCodeAndRedirect // Use the shared function after successful Google auth
);

// 3. Token Endpoint
app.post('/token', (req, res) => {
    const { grant_type, code, client_id, code_verifier } = req.body;

    if (grant_type !== 'authorization_code') {
        return res.status(400).json({ error: 'unsupported_grant_type' });
    }

    const stored = authorizationCodes[code];

    if (!stored || stored.expires < Date.now() || stored.client_id !== client_id) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Código inválido, expirado ou client_id não corresponde.' });
    }

    const verifierHashed = crypto.createHash('sha256').update(code_verifier).digest('base64url');
    if (verifierHashed !== stored.code_challenge) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE code_verifier inválido.' });
    }

    delete authorizationCodes[code]; // Code can only be used once

    // Issue JWT
    const payload = {
        iss: 'http://localhost:5000', // Issuer
        sub: stored.user.id, // Subject
        aud: client_id, // Audience
        email: stored.user.emails[0].value,
        name: stored.user.displayName,
    };

    const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

    res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
    });
});

// API endpoint to get user data
app.get('/api/user', (req, res) => {
    if (req.isAuthenticated()) {
        res.json(req.user);
    } else {
        res.status(401).json({ message: 'Not authenticated' });
    }
});

// Logout
app.get('/api/logout', (req, res, next) => {
  req.logout(function(err) {
    if (err) { return next(err); }
    req.session.destroy(() => {
        res.status(200).json({ message: 'Logged out successfully' });
    });
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));