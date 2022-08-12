import assert from 'assert';
import Express, { NextFunction, Request, Response } from 'express';
import { AttestationResult, Fido2Lib } from 'fido2-lib';
import { generateKeyPair, GenerateKeyPairResult, JWTPayload, jwtVerify, SignJWT } from 'jose';

/** Server runtime port */
const PORT = 8080;
/** Hostname that the server runs on - used by FIDO2 */
const HOSTNAME = "fido.mxblue.net.au"
/** Origin URL (with protocol and port) that responses should originate from */
const ORIGIN = "https://fido.mxblue.net.au"

type AsyncExpressHandlerFunction = (req: Request, res: Response, next: NextFunction) => Promise<void>;
type ExpressHandlerFunction = (req: Request, res: Response, next: NextFunction) => void;

/**
 * Wrap an async route handler in a catch to forward errors to `next()`
 * @param handler Async route handler function
 * @returns Wrapped route handler function
 */
function runAsync(handler: AsyncExpressHandlerFunction): ExpressHandlerFunction {
  return function (req, res, next) {
    handler(req, res, next)
      .catch(next);
  };
}

/** Request body for /register/start */
interface RegistrationStartBody {
  displayName: string;
  name: string;
}

/** Request body for /register/finish */
interface RegistrationFinishBody {
  token: string;
  result: AttestationResult;
}

/** JWT interface data passed around during registration */
type ChallengeJWT = JWTPayload & { 
  userName?: string;
  challenge: string; 
};

interface LoginStartBody {
  email?: string;
}

/** Data to represent a FIDO2 credential */
interface Credential {
  counter: number;
  credentialId: ArrayBuffer;
  publicKey: ArrayBuffer;
}

/** Basic user data to persist something resembling a user */
interface UserData {
  userName: string;
  displayName: string;
  credentials?: Credential[];
  userHandle?: string;
}

// Platform authenticators ('platform') - Uses Windows Hello
// Roaming authenticators ('cross-platform') - Uses FIDO2 key

// TODO: Test resident keys

const app = Express();
const fido2 = new Fido2Lib({
  timeout: 60,
  rpId: HOSTNAME,
  rpName: "MxBlue Server",
  attestation: "none",
  authenticatorAttachment: "cross-platform",
  authenticatorRequireResidentKey: false,
  authenticatorUserVerification: "preferred"
});
let serverKp: GenerateKeyPairResult = null;
generateKeyPair('ES256').then(kp => { 
  serverKp = kp;
  console.log('Keypair ready');
});

const users = new Map<string, UserData>();

/** Simple echoing route handler */
app.get('/echo', (_, res): void => {
  res.send('echo');
});

/** 
 * Registration start route, provided a RegistrationStartBody 
 * Returns a 200 with registration details on success, 400 on bad request
*/
app.post('/register/start', runAsync(async (req, res): Promise<void> => {
  // Parse and validate request body
  let body: RegistrationStartBody = null;
  try {
    body = JSON.parse(req.body);
    assert(typeof body.displayName === 'string');
    assert(typeof body.name === 'string');
  } catch (e) {
    console.error(e);
    res.status(400).json({ 'error': 'Invalid request' });
    return;
  }

  // Check username availability
  if (users.has(body.name)) {
    res.status(400).json({ 'error': 'Username in use' });
    return;
  }

  // Generate a user ID
  const userId = crypto.randomUUID();

  // Generate registration options
  const opts = await fido2.attestationOptions();
  opts.user.id = userId;
  opts.user.displayName = body.displayName;
  opts.user.name = body.name;

  // Persist user details to user data
  users.set(body.name, {
    userName: body.name,
    displayName: body.displayName
  });

  // Sign a JWT and store the user ID and challenge on it for later retrieval
  const jwt = await new SignJWT({ 
    sub: userId,
    userName: body.name,
    challenge: opts.challenge
   })
   .setExpirationTime('5m')
   .sign(serverKp.privateKey);

  // Send the registration options and signed JWT to the user
  res.json({
    'token': jwt,
    'options': opts
  });
  return;
}));

/** 
 * Registration finish route, provided a RegistrationFinishBody 
 * Returns 200 on success, 403 on attestation failure, 400 on bad request
*/
app.post('/register/finish', runAsync(async (req, res): Promise<void> => {
  // Parse and validate request body
  let body: RegistrationFinishBody = null;
  try {
    body = JSON.parse(req.body);
    assert(typeof body.token === 'string');
    assert(body.result !== null || body.result !== undefined);
  } catch (e) {
    console.error(e);
    res.status(400).json({ 'error': 'Invalid request' });
    return;
  }

  // Verify and decode the JWT
  const jwtDecode = await jwtVerify(body.token, serverKp.publicKey);
  const jwt = <ChallengeJWT> jwtDecode.payload;

  try {
    // Validate the attestation against the challenge
    const attestationRes = await fido2.attestationResult(body.result, { 
      challenge: jwt.challenge,
      factor: 'first',
      origin: ORIGIN
    });

    // Fetch the user object
    const user = users.get(jwt.userName);

    // Update the user ID and append these credentials to the list
    user.userHandle = jwt.sub;
    user.credentials.push({
      counter: attestationRes.authnrData.get('counter'),
      credentialId: attestationRes.authnrData.get('credId'),
      publicKey: attestationRes.authnrData.get('credentialPublicKeyPem')
    });

    res.json({ 'status': 'ok' });

  } catch (e) {
    console.error(e);
    res.status(403).json({ 'error': 'Attestation failed' });
    return;
  }
}));

/** 
 * Login start route, provided a LoginStartBody 
 * Returns 200 with a login challenge on sucess, 403 on invalid username, 400 on bad request 
*/
app.post('/login', runAsync(async (req, res): Promise<void> => {
  // Default the body to an empty object
  const rawBody = req.body != null ? req.body : "{}";
  // Parse and validate request body
  let body: LoginStartBody = null;
  try {
    body = JSON.parse(rawBody);
    assert(body.email == null || typeof body.email === 'string');
  } catch (e) {
    console.error(e);
    res.status(400).json({ 'error': 'Invalid request' });
    return;
  }

  // Generate assertion
  const opts = await fido2.assertionOptions();

  // `sub` and `userName` will only get set if we have a valid email
  let sub = null;
  let userName = null;

  // Add in allowed credentials we we're treating it as a email based login
  if (body.email != null) {
    // Handle as non-resident key login
    const user = users.get(body.email);
    // Throw a 403 if we receive an invalid email
    if (user == null) {
      res.status(403).json({ 'error': 'Invalid username' });
      return;
    }

    // Add in credentials from request user
    opts.allowCredentials = user.credentials.map(c => ({ id: c.credentialId, type: 'public-key' }));

    sub = user.userHandle;
    userName = user.userName;
  }

  // Sign a JWT and store the user ID and challenge on it for later retrieval
  const jwt = await new SignJWT({
    sub: sub,
    userName: userName,
    challenge: opts.challenge
  })
  .setExpirationTime('5m')
  .sign(serverKp.privateKey);

  // Send the login options and signed JWT to the user
  res.json({
    'token': jwt,
    'options': opts
  });
  return;
}));

app.listen(PORT, () => { console.log(`Listening on port ${PORT}`) });