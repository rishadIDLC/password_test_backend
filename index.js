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

app.use(cors({
  origin,
  credentials: true,
}));

// In-memory stores
const challenges = {}; // Stores challenges temporarily
const users = {}; // Key: username, value: user data
const authenticators = {}; // Key: credentialID, value: authenticator + username

console.log('Server started. In-memory stores are empty.');

// 1. Registration Options
app.get('/generate-registration-options', async (req, res) => {
  const { username } = req.query;
  if (!username) return res.status(400).json({ error: 'Username required' });
  if (Object.values(users).find(u => u.username === username)) {
    return res.status(400).json({ error: 'Username already taken' });
  }

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userID: username,
    userName: username,
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      requireResidentKey: true,
      userVerification: 'required',
    },
    timeout: 60000,
  });

  challenges[username] = options.challenge;
  res.json(options);
});

// 2. Verify Registration
app.post('/verify-registration', async (req, res) => {
  const { username, response } = req.body;
  const expectedChallenge = challenges[username];
  if (!expectedChallenge) return res.status(400).json({ error: 'No challenge found' });

  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });

    const { verified, registrationInfo } = verification;
    if (!verified || !registrationInfo) return res.status(400).json({ error: 'Verification failed' });

    const { credentialID, credentialPublicKey, counter } = registrationInfo;
    const base64ID = Buffer.from(credentialID).toString('base64url');

    // Store user and authenticator
    users[username] = { username, credentialID: base64ID };
    authenticators[base64ID] = {
      credentialID: base64ID,
      credentialPublicKey: Buffer.from(credentialPublicKey).toString('base64url'),
      counter,
      username,
    };

    delete challenges[username];
    res.json({ verified: true });
  } catch (e) {
    console.error('[verify-registration]', e);
    res.status(500).json({ error: 'Registration verification failed' });
  }
});

// 3. Authentication Options (username-less)
app.get('/generate-authentication-options', async (req, res) => {
  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: 'required',
    timeout: 60000,
  });

  // Save challenge globally (temporary)
  challenges['login'] = options.challenge;
  res.json(options);
});

// 4. Verify Authentication (username-less)
app.post('/verify-authentication', async (req, res) => {
  const { response } = req.body;
  const expectedChallenge = challenges['login'];
  if (!expectedChallenge) return res.status(400).json({ error: 'No login challenge' });

  try {
    const credentialID = response.rawId;
    const base64ID = Buffer.from(credentialID, 'base64url').toString('base64url');
    const auth = authenticators[base64ID];
    if (!auth) return res.status(400).json({ error: 'Credential not found' });

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: Buffer.from(auth.credentialID, 'base64url'),
        credentialPublicKey: Buffer.from(auth.credentialPublicKey, 'base64url'),
        counter: auth.counter,
      },
      requireUserVerification: true,
    });

    const { verified, authenticationInfo } = verification;
    if (verified) {
      auth.counter = authenticationInfo.newCounter;
      delete challenges['login'];
      return res.json({ verified: true, username: auth.username });
    } else {
      return res.status(400).json({ error: 'Authentication failed' });
    }
  } catch (e) {
    console.error('[verify-authentication]', e);
    res.status(500).json({ error: 'Authentication verification failed' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
