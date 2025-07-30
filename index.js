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

// In-memory stores with improved structure
const userChallenges = {}; // Stores temporary challenges
const userAuthenticators = {}; // Stores permanent authenticator data

// 1. Generate Registration Options
app.get('/generate-registration-options', async (req, res) => {
  const { username } = req.query;
  console.log(`\n[GET /generate-registration-options] for username: ${username}`);

  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  if (userAuthenticators[username]) {
    return res.status(400).json({ error: 'Username already registered' });
  }

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userName: username,
    userDisplayName: username,
    excludeCredentials: [],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required',
      requireResidentKey: true,
      residentKey: 'required',
    },
  });

  userChallenges[username] = {
    challenge: options.challenge,
    timestamp: Date.now()
  };

  console.log(`Generated registration challenge for ${username}`);
  res.json(options);
});

// 2. Verify Registration Response
app.post('/verify-registration', async (req, res) => {
  const { username, response } = req.body;
  console.log(`\n[POST /verify-registration] for username: ${username}`);

  const userChallenge = userChallenges[username];

  if (!userChallenge) {
    return res.status(400).json({ error: 'Registration session expired. Please try again.' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: userChallenge.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });

    if (verification.verified && verification.registrationInfo) {
      const { credentialPublicKey, credentialID, counter } = verification.registrationInfo;

      userAuthenticators[username] = {
        credentialID: Buffer.from(credentialID).toString('base64url'),
        credentialPublicKey: Buffer.from(credentialPublicKey).toString('base64url'),
        counter,
        transports: response.response.transports,
      };

      delete userChallenges[username];
      return res.json({ verified: true });
    }
    return res.status(400).json({ error: 'Verification failed' });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ error: error.message });
  }
});

// 3. Generate Authentication Options
app.get('/generate-authentication-options', async (req, res) => {
  const { username } = req.query;
  console.log(`\n[GET /generate-authentication-options] for username: ${username}`);

  if (!username || !userAuthenticators[username]) {
    return res.status(400).json({ error: 'User not registered' });
  }

  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: 'required',
  });

  userChallenges[username] = {
    challenge: options.challenge,
    timestamp: Date.now()
  };

  console.log(`Generated authentication challenge for ${username}`);
  res.json(options);
});

// 4. Verify Authentication Response
app.post('/verify-authentication', async (req, res) => {
  const { username, response } = req.body;
  console.log(`\n[POST /verify-authentication] for username: ${username}`);

  const userChallenge = userChallenges[username];
  const authenticator = userAuthenticators[username];

  if (!userChallenge || !authenticator) {
    console.log('Available users:', Object.keys(userAuthenticators));
    return res.status(400).json({ 
      error: 'Authentication session expired or user not found',
      availableUsers: Object.keys(userAuthenticators) // For debugging
    });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: userChallenge.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: Buffer.from(authenticator.credentialID, 'base64url'),
        credentialPublicKey: Buffer.from(authenticator.credentialPublicKey, 'base64url'),
        counter: authenticator.counter,
        transports: authenticator.transports,
      },
      requireUserVerification: true,
    });

    if (verification.verified) {
      userAuthenticators[username].counter = verification.authenticationInfo.newCounter;
      delete userChallenges[username];
      return res.json({ verified: true });
    }
    return res.status(400).json({ error: 'Authentication failed' });
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Configured for:', {
    rpName,
    rpID,
    origin
  });
});