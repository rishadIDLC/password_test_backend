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
const rpID = 'password-test-frontend.vercel.app';
const origin = `https://${rpID}`;

app.use(cors({
  origin: origin,
  credentials: true,
}));

// In-memory store
const users = {}; // stores challenges
const authenticators = {}; // stores registered passkeys

// 1. Generate Registration Options
app.get('/generate-registration-options', async (req, res) => {
  const { username } = req.query;
  if (!username) return res.status(400).json({ error: 'Username is required' });
  if (authenticators[username]) return res.status(400).json({ error: 'Username already taken' });

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userID: username,
    userName: username,
    excludeCredentials: [],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required',
      requireResidentKey: true,
    },
    timeout: 60000,
  });

  users[username] = { currentChallenge: options.challenge };
  res.json(options);
});

// 2. Verify Registration
app.post('/verify-registration', async (req, res) => {
  const { username, response } = req.body;
  const user = users[username];
  if (!user) return res.status(400).json({ error: 'No challenge found' });

  try {
    const { verified, registrationInfo } = await verifyRegistrationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });

    if (!verified || !registrationInfo) return res.status(400).json({ error: 'Verification failed' });

    const { credentialPublicKey, credentialID, counter } = registrationInfo;
    authenticators[username] = {
      credentialID: Buffer.from(credentialID).toString('base64url'),
      credentialPublicKey: Buffer.from(credentialPublicKey).toString('base64url'),
      counter,
      transports: response.response.transports,
    };

    delete users[username];
    res.json({ verified: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal error', details: err.message });
  }
});

// 3. Generate Authentication Options
app.get('/generate-authentication-options', async (req, res) => {
  const { username } = req.query;
  if (!authenticators[username]) return res.status(400).json({ error: 'User not registered' });

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: [
      {
        id: authenticators[username].credentialID,
        type: 'public-key',
        transports: authenticators[username].transports,
      },
    ],
    userVerification: 'required',
    timeout: 60000,
  });

  users[username] = { currentChallenge: options.challenge };
  res.json(options);
});

// 4. Verify Authentication
app.post('/verify-authentication', async (req, res) => {
  const { username, response } = req.body;
  const user = users[username];
  const auth = authenticators[username];

  if (!user || !auth) return res.status(400).json({ error: 'User or challenge not found' });

  try {
    const verifiedResp = await verifyAuthenticationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: Buffer.from(auth.credentialID, 'base64url'),
        credentialPublicKey: Buffer.from(auth.credentialPublicKey, 'base64url'),
        counter: auth.counter,
        transports: auth.transports,
      },
      requireUserVerification: true,
    });

    const { verified, authenticationInfo } = verifiedResp;
    if (!verified) return res.status(400).json({ error: 'Authentication failed' });

    authenticators[username].counter = authenticationInfo.newCounter;
    delete users[username];

    res.json({ verified: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal error', details: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
