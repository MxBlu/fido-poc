import assert from "assert";
import { Request, Response } from "express";
import { PublicKeyCredentialRequestOptions } from "fido2-lib";
import { SignJWT } from "jose";
import { ChallengeJWT } from "../models.js";
import { Fido2, ServerKP, Users } from "../runtime_globals.js";
import { b64_decode, b64_encode } from "../utils/b64.js";
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
  challenge_b64?: string;
  options?: PublicKeyCredentialRequestOptions;
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

  // `sub` and `userName` will only get set if we have a valid username
  let sub = null;
  let userName = null;

  // Add in allowed credentials we we're treating it as a username based login
  if (body.userName != null && body.userName.length > 0) {
    logger.info(`Attestation request for username: ${body.userName}`);
    // Handle as non-resident key login
    const user = Users.get(body.userName);
    // Throw a 403 if we receive an invalid username
    if (user == null) {
      logger.warn(`Unknown username: ${body.userName}`);
      res.status(403).json(<LoginStartResponse> { 'error': 'Invalid username' });
      return;
    }

    // Add in credentials from request user
    opts.allowCredentials = user.credentials.map(c => ({ id: b64_decode(c.credentialId_b64), type: 'public-key' }));

    sub = user.userHandle;
    userName = user.userName;
  } else {
    logger.info(`General attestation request`);
  }

  // Encode the challenge to base 64
  const challenge_b64 = b64_encode(opts.challenge);

  // Sign a JWT and store the user ID and challenge on it for later retrieval
  const jwt = await new SignJWT(<ChallengeJWT> {
    sub: sub,
    userName: userName,
    challenge_b64: challenge_b64
  })
  .setExpirationTime('5m')
  .setProtectedHeader({ alg: 'ES256' })
  .sign(ServerKP.privateKey);

  // Send the login options and signed JWT to the user
  res.json(<LoginStartResponse> {
    'token': jwt,
    'challenge_b64': challenge_b64,
    'options': opts
  });
  return;
}