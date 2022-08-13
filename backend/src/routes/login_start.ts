import assert from "assert";
import { Request, Response } from "express";
import { SignJWT } from "jose";
import { Fido2, ServerKP, Users } from "../runtime_globals.js";
import { Logger } from "../utils/logger.js";

/** Module logger */
const logger = new Logger("LoginStart");

/** Request body for /login/start */
interface LoginStartBody {
  userName?: string;
}

/** 
 * Login start route, provided a LoginStartBody 
 * Returns 200 with a login challenge on sucess, 403 on invalid username, 400 on bad request 
*/
export async function loginStartHandle(req: Request, res: Response): Promise<void> {
  // Default the body to an empty object
  const rawBody = req.body != null ? req.body : "{}";
  // Parse and validate request body
  let body: LoginStartBody = null;
  try {
    body = JSON.parse(rawBody);
    assert(body.userName == null || typeof body.userName === 'string');
  } catch (e) {
    const error = <Error> e;
    logger.error(error.message);
    console.error(error.stack);
    res.status(400).json({ 'error': 'Invalid request' });
    return;
  }

  // Generate assertion
  const opts = await Fido2.assertionOptions();

  // `sub` and `userName` will only get set if we have a valid username
  let sub = null;
  let userName = null;

  // Add in allowed credentials we we're treating it as a username based login
  if (body.userName != null) {
    logger.info(`Attestation request for username: ${body.userName}`);
    // Handle as non-resident key login
    const user = Users.get(body.userName);
    // Throw a 403 if we receive an invalid username
    if (user == null) {
      logger.warn(`Unknown username: ${body.userName}`);
      res.status(403).json({ 'error': 'Invalid username' });
      return;
    }

    // Add in credentials from request user
    opts.allowCredentials = user.credentials.map(c => ({ id: c.credentialId, type: 'public-key' }));

    sub = user.userHandle;
    userName = user.userName;
  } else {
    logger.info(`General attestation request`);
  }

  // Sign a JWT and store the user ID and challenge on it for later retrieval
  const jwt = await new SignJWT({
    sub: sub,
    userName: userName,
    challenge: opts.challenge
  })
  .setExpirationTime('5m')
  .sign(ServerKP.privateKey);

  // Send the login options and signed JWT to the user
  res.json({
    'token': jwt,
    'options': opts
  });
  return;
}