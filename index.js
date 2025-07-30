// server.js
import express from 'express';
import cors from 'cors';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

const app = express();
app.use(express.json());

const rpName = 'Gemini WebAuthn Demo';
const rpID = 'password-test-frontend.vercel.app'; // Your frontend domain
const origin = `https://${rpID}`;

// Enable CORS only for your frontend
app.use(cors({
  origin,
  credentials: true,
}));

// Temporary in-memory stores
const users = {};         // username -> { currentChallenge }
const authenticators = {}; // username -> authenticator data

// 1. Registration - Generate options
app.get('/generate-registration-options', async (req, res) => {
  const { username } = req.query;
  console.log(`\n[GET /generate-registration-options] for username: ${username}`);

  if (!username) {
    console.log('[ERROR] Username is required');
    return res.status(400).json({ error: 'Username is required' });
  }

  if (authenticators[username]) {
    console.log(`[ERROR] Username "${username}" is already registered.`);
    return res.status(400).json({ error: 'Username already taken' });
  }

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: username,
    excludeCredentials: [],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required', 
      // **FIX**: Change from false to true. This creates a "discoverable credential" (resident key),
      // which is more robust and easily found by the browser during login.
      requireResidentKey: true,
    },
  });

// 2. Registration - Verify response
app.post('/verify-registration', async (req, res) => {
  const { username, response } = req.body;
  const user = users[username];
  if (!user) return res.status(400).json({ error: 'User not found or registration expired.' });

  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });

    const { verified, registrationInfo } = verification;
    if (verified && registrationInfo) {
      const { credentialPublicKey, credentialID, counter } = registrationInfo;

      authenticators[username] = {
        credentialID: Buffer.from(credentialID).toString('base64url'),
        credentialPublicKey: Buffer.from(credentialPublicKey).toString('base64url'),
        counter,
        transports: response.response.transports,
      };

      delete users[username];
      res.json({ verified: true });
    } else {
      res.status(400).json({ error: 'Could not verify registration.' });
    }
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: err.message });
  }
});

// 3. Authentication - Generate options
app.get('/generate-authentication-options', async (req, res) => {
  const { username } = req.query;
  if (!authenticators[username]) {
    return res.status(400).json({ error: 'User not registered.' });
  }

  const options = await generateAuthenticationOptions({
    rpID,
    // ⚠️ Don't send allowCredentials if using resident keys
    userVerification: 'required',
  });

  users[username] = { currentChallenge: options.challenge };

  res.json(options);
});

// 4. Authentication - Verify response
app.post('/verify-authentication', async (req, res) => {
  const { username, response } = req.body;
  const user = users[username];
  const authenticator = authenticators[username];

  if (!user || !authenticator) {
    return res.status(400).json({ error: 'User not found or authentication expired.' });
  }

  try {
    const authenticatorDevice = {
      credentialID: Buffer.from(authenticator.credentialID, 'base64url'),
      credentialPublicKey: Buffer.from(authenticator.credentialPublicKey, 'base64url'),
      counter: authenticator.counter,
      transports: authenticator.transports,
    };

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: authenticatorDevice,
      requireUserVerification: true,
    });

    const { verified, authenticationInfo } = verification;

    if (verified) {
      authenticators[username].counter = authenticationInfo.newCounter;
      delete users[username];
      res.json({ verified: true });
    } else {
      res.status(400).json({ error: 'Could not verify authentication.' });
    }
  } catch (err) {
    console.error('Authentication error:', err);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
