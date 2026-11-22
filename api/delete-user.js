const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function getServiceAccount() {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    try {
      return JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    } catch (e) {
      console.error("FIREBASE_SERVICE_ACCOUNT parse error:", e.message);
    }
  }

  const candidatePaths = [
    path.join(process.cwd(), 'serviceAccountKey.json'),
    path.join(__dirname, 'serviceAccountKey.json'),
    path.join(__dirname, '..', 'serviceAccountKey.json')
  ];

  for (const p of candidatePaths) {
    if (fs.existsSync(p)) {
      try {
        return JSON.parse(fs.readFileSync(p, 'utf8'));
      } catch (e) {
        console.error(`Error reading ${p}:`, e.message);
      }
    }
  }
  return null;
}

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

let cachedToken = null;
let tokenExpiry = 0;

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

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const { email, uid } = req.body || {};
  if (!email && !uid) {
    return res.status(400).json({ error: "Email or UID parameter is required." });
  }

  const serviceAccount = getServiceAccount();
  if (!serviceAccount) {
    return res.status(503).json({
      error: "SERVICE_KEY_REQUIRED",
      message: "Please add FIREBASE_SERVICE_ACCOUNT environment variable in Vercel settings (or place 'serviceAccountKey.json' in folder)."
    });
  }

  try {
    const accessToken = await getGoogleAccessToken(serviceAccount);
    const projectId = serviceAccount.project_id || 'learnly-a90fb';
    let targetUid = uid;
    let targetEmail = email ? email.trim() : null;

    // Look up user UID by email if not provided
    if (!targetUid && targetEmail) {
      const lookupRes = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:lookup`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email: [targetEmail] })
      });
      const lookupData = await lookupRes.json();
      if (lookupRes.ok && lookupData.users && lookupData.users.length > 0) {
        targetUid = lookupData.users[0].localId;
      } else {
        return res.status(404).json({ error: `User '${targetEmail}' was not found in Firebase Authentication.` });
      }
    }

    // 1. Delete user from Firebase Authentication
    const authRes = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:delete`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ localId: targetUid })
    });

    // 2. Delete user document from Cloud Firestore (users collection)
    try {
      await fetch(`https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users/${targetUid}`, {
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

    console.log(`User ${targetEmail || targetUid} permanently deleted from Firebase.`);
    return res.status(200).json({
      success: true,
      message: `User '${targetEmail || targetUid}' was permanently deleted from Firebase Authentication and Firestore database.`
    });

  } catch (err) {
    console.error("Delete user error:", err);
    return res.status(500).json({ error: err.message });
  }
};
