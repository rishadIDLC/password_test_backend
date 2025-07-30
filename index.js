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

// Enhanced storage with debugging capabilities
const userStore = {
  challenges: {},
  authenticators: {},
  
  // Helper methods
  addAuthenticator(username, authenticator) {
    this.authenticators[username.toLowerCase()] = authenticator;
    console.log(`Registered authenticator for ${username}. Current users:`, Object.keys(this.authenticators));
  },
  
  getAuthenticator(username) {
    return this.authenticators[username.toLowerCase()];
  },
  
  addChallenge(username, challenge) {
    this.challenges[username.toLowerCase()] = {
      challenge,
      timestamp: Date.now()
    };
  },
  
  getChallenge(username) {
    return this.challenges[username.toLowerCase()];
  },
  
  clearChallenge(username) {
    delete this.challenges[username.toLowerCase()];
  }
};

// 1. Generate Registration Options
app.get('/generate-registration-options', async (req, res) => {
  const username = req.query.username?.trim();
  console.log(`\n[REGISTER] Start for username: ${username}`);

  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  if (userStore.getAuthenticator(username)) {
    console.log(`[CONFLICT] Username ${username} already exists`);
    return res.status(409).json({ error: 'Username already registered' });
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

  userStore.addChallenge(username, options.challenge);
  console.log(`[REGISTER] Challenge stored for ${username}`);
  res.json(options);
});

// 2. Verify Registration Response
app.post('/verify-registration', async (req, res) => {
  const { username, response } = req.body;
  const normalizedUsername = username?.toLowerCase().trim();
  console.log(`\n[REGISTER] Verify for username: ${normalizedUsername}`);

  const userChallenge = userStore.getChallenge(normalizedUsername);

  if (!userChallenge) {
    console.log('[ERROR] No challenge found for user:', normalizedUsername);
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

      userStore.addAuthenticator(normalizedUsername, {
        credentialID: Buffer.from(credentialID).toString('base64url'),
        credentialPublicKey: Buffer.from(credentialPublicKey).toString('base64url'),
        counter,
        transports: response.response.transports || ['internal'],
      });

      userStore.clearChallenge(normalizedUsername);
      console.log(`[SUCCESS] User ${normalizedUsername} registered successfully`);
      return res.json({ verified: true, username: normalizedUsername });
    }
    
    return res.status(400).json({ error: 'Verification failed' });
  } catch (error) {
    console.error('[ERROR] Registration failed:', error);
    return res.status(500).json({ error: 'Registration failed: ' + error.message });
  }
});

// 3. Generate Authentication Options
app.get('/generate-authentication-options', async (req, res) => {
  const username = req.query.username?.trim();
  const normalizedUsername = username?.toLowerCase();
  console.log(`\n[LOGIN] Start for username: ${normalizedUsername}`);

  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  const authenticator = userStore.getAuthenticator(normalizedUsername);
  if (!authenticator) {
    console.log(`[ERROR] No authenticator found for: ${normalizedUsername}`);
    console.log('Registered users:', Object.keys(userStore.authenticators));
    return res.status(404).json({ 
      error: 'User not registered',
      registeredUsers: Object.keys(userStore.authenticators) // For debugging
    });
  }

  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: 'required',
  });

  userStore.addChallenge(normalizedUsername, options.challenge);
  console.log(`[LOGIN] Challenge stored for ${normalizedUsername}`);
  res.json(options);
});

// 4. Verify Authentication Response
app.post('/verify-authentication', async (req, res) => {
  const { username, response } = req.body;
  const normalizedUsername = username?.toLowerCase().trim();
  console.log(`\n[LOGIN] Verify for username: ${normalizedUsername}`);

  const userChallenge = userStore.getChallenge(normalizedUsername);
  const authenticator = userStore.getAuthenticator(normalizedUsername);

  if (!userChallenge || !authenticator) {
    console.log(`[ERROR] Challenge or authenticator missing for: ${normalizedUsername}`);
    console.log('Current challenges:', Object.keys(userStore.challenges));
    console.log('Registered users:', Object.keys(userStore.authenticators));
    return res.status(400).json({ 
      error: 'Authentication session expired or user not found',
      availableUsers: Object.keys(userStore.authenticators)
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
      authenticator.counter = verification.authenticationInfo.newCounter;
      userStore.clearChallenge(normalizedUsername);
      console.log(`[SUCCESS] User ${normalizedUsername} authenticated`);
      return res.json({ verified: true, username: normalizedUsername });
    }
    
    return res.status(401).json({ error: 'Authentication failed' });
  } catch (error) {
    console.error('[ERROR] Authentication failed:', error);
    return res.status(500).json({ error: 'Authentication failed: ' + error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Configuration:', { rpName, rpID, origin });
});