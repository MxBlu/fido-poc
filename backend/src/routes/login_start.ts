import assert from "assert";
import * as base64buffer from 'base64-arraybuffer';
import { Request, Response } from "express";
import { SignJWT } from "jose";
import { AssertionOptionsWireFormat, ChallengeJWT } from "../models.js";
import { Fido2, ServerKP, Users } from "../runtime_globals.js";
import { Logger } from "../utils/logger.js";

/** Module logger */
const logger = new Logger("LoginStart");

/** Request body for /login/start */
interface LoginStartRequest {
  userName?: string;
}

/** Response body for /login/start */
interface LoginStartResponse {
  error?: string;
  token?: string;
  options?: AssertionOptionsWireFormat;
}

/** 
 * Login start route, provided a LoginStartBody 
 * Returns 200 with a login challenge on sucess, 403 on invalid username, 400 on bad request 
*/
export async function loginStartHandle(req: Request, res: Response): Promise<void> {
  // Parse and validate request body
  const body: LoginStartRequest = req.body ?? {};
  try {
    assert(body.userName == null || typeof body.userName === 'string', "Username is not a string");
  } catch (e) {
    const error = <Error> e;
    logger.warn(error.message);
    res.status(400).json({ 'error': error.message });
    return;
  }

  // Generate assertion
  const opts = await Fido2.assertionOptions();
  // Encode all ArrayBuffers to base 64
  const transferrableOpts: AssertionOptionsWireFormat = {
    ...opts,
    challenge: base64buffer.encode(opts.challenge),
    rawChallenge: opts.rawChallenge ? base64buffer.encode(opts.rawChallenge) : null,
    allowCredentials: []
  };

  // `sub` and `userName` will only get set if we have a valid username
  let sub = null;
  let userName = null;

  if (body.userName != null && body.userName.length > 0) {
    // Add in allowed credentials we we're treating it as a username based login
    logger.info(`Assertion request for username: ${body.userName}`);

    // Handle as non-resident key login
    const user = Users.get(body.userName);
    // Throw a 403 if we receive an invalid username
    if (user == null) {
      logger.warn(`Unknown username: ${body.userName}`);
      res.status(403).json(<LoginStartResponse> { 'error': 'Invalid username' });
      return;
    }

    // Add in credentials from request user
    transferrableOpts.allowCredentials = user.credentials.map(c => ({ id: c.credentialId_b64, type: 'public-key' }));

    sub = user.userHandle;
    userName = user.userName;
  } else {
    // If no username is present, treat it as resident key login
    logger.info(`General attestation request`);
  }

  // Sign a JWT and store the user ID and challenge on it for later retrieval
  const jwt = await new SignJWT(<ChallengeJWT> {
    sub: sub,
    userName: userName,
    challenge_b64: transferrableOpts.challenge
  })
  .setExpirationTime('5m')
  .setProtectedHeader({ alg: 'ES256' })
  .sign(ServerKP.privateKey);

  // Send the login options and signed JWT to the user
  res.json(<LoginStartResponse> {
    'token': jwt,
    'options': transferrableOpts
  });
  return;
}