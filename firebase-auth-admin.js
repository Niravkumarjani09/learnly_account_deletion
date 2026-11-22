const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Base64URL encoding helper
function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

// Locate service account configuration
function getServiceAccount() {
  // 1. Environment variable (for Vercel deployment)
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    try {
      return JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    } catch (e) {
      console.error("Failed to parse FIREBASE_SERVICE_ACCOUNT env var:", e.message);
    }
  }

  // 2. Local serviceAccountKey.json file
  const candidatePaths = [
    path.join(process.cwd(), 'serviceAccountKey.json'),
    path.join(__dirname, 'serviceAccountKey.json'),
    path.join(__dirname, '..', 'serviceAccountKey.json')
  ];

  for (const p of candidatePaths) {
    if (fs.existsSync(p)) {
      try {
        const data = JSON.parse(fs.readFileSync(p, 'utf8'));
        return data;
      } catch (e) {
        console.error(`Error reading ${p}:`, e.message);
      }
    }
  }

  return null;
}

// Generate signed JWT for Google OAuth2
function createSignedJWT(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: serviceAccount.client_email,
    sub: serviceAccount.client_email,
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
    scope: 'https://www.googleapis.com/auth/identitytoolkit https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/datastore'
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signInput = `${encodedHeader}.${encodedPayload}`;

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signInput);
  const signature = signer.sign(serviceAccount.private_key, 'base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return `${signInput}.${signature}`;
}

// Token cache
let cachedToken = null;
let tokenExpiry = 0;

// Fetch or reuse Google OAuth 2.0 access token
async function getGoogleAccessToken(serviceAccount) {
  const now = Date.now();
  if (cachedToken && tokenExpiry > now + 60000) {
    return cachedToken;
  }

  const jwt = createSignedJWT(serviceAccount);
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${encodeURIComponent(jwt)}`
  });

  const data = await response.json();
  if (!response.ok || !data.access_token) {
    throw new Error(`Google OAuth error: ${data.error_description || data.error || JSON.stringify(data)}`);
  }

  cachedToken = data.access_token;
  tokenExpiry = now + (data.expires_in * 1000);
  return cachedToken;
}

// Query user in Firebase Authentication by email
async function getUserByEmail(email, serviceAccount) {
  const accessToken = await getGoogleAccessToken(serviceAccount);
  const projectId = serviceAccount.project_id || 'learnly-a90fb';

  const response = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:lookup`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ email: [email.trim()] })
  });

  const data = await response.json();
  if (response.ok && data.users && data.users.length > 0) {
    const u = data.users[0];
    return {
      uid: u.localId,
      email: u.email,
      displayName: u.displayName || 'Registered User',
      createdAt: u.createdAt,
      lastLoginAt: u.lastLoginAt,
      providers: (u.providerUserInfo || []).map(p => p.providerId)
    };
  }
  return null;
}

// Delete user from Firebase Authentication & Firestore
async function deleteUserByUid(uid, serviceAccount) {
  const accessToken = await getGoogleAccessToken(serviceAccount);
  const projectId = serviceAccount.project_id || 'learnly-a90fb';

  // 1. Delete from Firebase Authentication
  const authRes = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:delete`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ localId: uid })
  });

  // 2. Delete user document from Cloud Firestore (users collection)
  try {
    await fetch(`https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${uid}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });
  } catch (fsErr) {
    console.warn("Firestore delete notice:", fsErr.message);
  }

  const authData = await authRes.json();
  if (!authRes.ok) {
    throw new Error(`Firebase Auth deletion error: ${authData.error?.message || JSON.stringify(authData)}`);
  }
  return true;
}

module.exports = {
  getServiceAccount,
  getUserByEmail,
  deleteUserByUid
};
