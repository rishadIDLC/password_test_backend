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

// In-memory stores
const users = {};
const authenticators = {};

console.log('Server started. In-memory stores are empty.');

// 1. Generate Registration Options
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
    userDisplayName: username,
    excludeCredentials: [],
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      userVerification: 'required',
      requireResidentKey: true,
      residentKey: 'required',
    },
    attestation: 'direct',
    supportedAlgorithmIDs: [-7, -257], // ES256 and RS256
  });

  users[username] = {
    currentChallenge: options.challenge,
  };
  
  console.log(` -> Stored challenge for "${username}". Current users with challenges:`, Object.keys(users));
  console.log(` -> Sending options to frontend:`, options);

  res.json(options);
});

// 2. Verify Registration Response
app.post('/verify-registration', async (req, res) => {
  const { username, response } = req.body;
  console.log(`\n[POST /verify-registration] for username: ${username}`);
  console.log(' -> Current users with challenges:', Object.keys(users));

  const user = users[username];

  if (!user) {
    console.log(`[ERROR] No challenge found for user "${username}". Maybe server restarted?`);
    return res.status(400).json({ error: 'User not found or registration expired. Please try registering again.' });
  }

  try {
    console.log(' -> Verifying registration response with expected challenge:', user.currentChallenge);
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });

    const { verified, registrationInfo } = verification;
    console.log(` -> Verification result: ${verified}`);

    if (verified && registrationInfo) {
      console.log(' -> Verification successful. Storing new authenticator.');
      const { credentialPublicKey, credentialID, counter } = registrationInfo;

      authenticators[username] = {
        credentialID: Buffer.from(credentialID).toString('base64url'),
        credentialPublicKey: Buffer.from(credentialPublicKey).toString('base64url'),
        counter,
        transports: response.response.transports,
      };
      
      console.log(' -> Registered authenticators:', Object.keys(authenticators));

      delete users[username];
      res.json({ verified: true });
    } else {
      res.status(400).json({ error: 'Could not verify registration.' });
    }
  } catch (error) {
    console.error('[ERROR] /verify-registration:', error);
    res.status(500).json({ error: 'Verification failed', details: error.message });
  }
});

// 3. Generate Authentication Options
app.get('/generate-authentication-options', async (req, res) => {
  const { username } = req.query;
  console.log(`\n[GET /generate-authentication-options] for username: ${username}`);

  // For discoverable credentials, we don't need to provide allowCredentials
  // The browser will find the right credential automatically
  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: 'required',
  });

  // Store the challenge for this user
  users[username] = { currentChallenge: options.challenge };
  console.log(` -> Stored challenge for "${username}". Current users with challenges:`, Object.keys(users));
  console.log(` -> Sending options to frontend:`, options);

  res.json(options);
});

// 4. Verify Authentication Response
app.post('/verify-authentication', async (req, res) => {
  const { username, response } = req.body;
  console.log(`\n[POST /verify-authentication] for username: ${username}`);
  console.log(' -> Current users with challenges:', Object.keys(users));
  
  const user = users[username];
  const authenticator = authenticators[username];

  if (!user || !authenticator) {
    console.log(`[ERROR] User or authenticator not found for "${username}".`);
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
    console.log(` -> Verification result: ${verified}`);

    if (verified) {
      console.log(' -> Verification successful. Updating counter.');
      authenticators[username].counter = authenticationInfo.newCounter;
      delete users[username];
      res.json({ verified: true });
    } else {
      res.status(400).json({ error: 'Could not verify authentication.' });
    }
  } catch (error) {
    console.error('[ERROR] /verify-authentication:', error);
    res.status(500).json({ error: 'Verification failed', details: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});