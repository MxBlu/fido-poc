import assert from "assert";
import * as crypto from "crypto";
import { Request, Response } from "express";
import { SignJWT } from "jose";
import { AttestationOptionsWireFormat, ChallengeJWT } from "../models.js";
import { Fido2, ServerKP, Users } from "../runtime_globals.js";
import { b64_encode } from "../utils/b64.js";
import { Logger } from "../utils/logger.js";

/** Module logger */
const logger = new Logger("RegistrationStart");

/** Request body for /register/start */
interface RegistrationStartRequest {
  displayName: string;
  userName: string;
}

/** Response body for /register/start */
interface RegistrationStartResponse {
  error?: string;
  token?: string;
  options?: AttestationOptionsWireFormat;
}

/** 
 * Registration start route, provided a RegistrationStartBody 
 * 
 * Returns a 200 with registration details on success, 400 on bad request
*/
export async function registerStartHandle(req: Request, res: Response): Promise<void> {
  // Parse and validate request body
  const body: RegistrationStartRequest = req.body ?? {};
  try {
    assert(typeof body.displayName === 'string', 'Display name is not present or not a string');
    assert(typeof body.userName === 'string' && body.userName.length > 0, 'Username is not present or not a string');
  } catch (e) {
    const error = <Error> e;
    logger.warn(error.message);
    res.status(400).json(<RegistrationStartResponse> { 'error': error.message });
    return;
  }

  // Check username availability
  if (Users.has(body.userName)) {
    logger.warn(`Username in use: ${body.userName}`);
    res.status(400).json(<RegistrationStartResponse> { 'error': 'Username in use' });
    return;
  }
  
  logger.info(`Registration request for username: ${body.userName}`);

  // Generate a user ID
  const userId = crypto.randomUUID();

  // Generate registration options
  const opts = await Fido2.attestationOptions();
  opts.user.id = b64_encode(userId);
  opts.user.displayName = body.displayName;
  opts.user.name = body.userName;

  // Persist user details to user data
  Users.set(body.userName, {
    userName: body.userName,
    displayName: body.displayName
  });

  // Encode the challenge to base 64
  const challenge_b64 = b64_encode(opts.challenge);

  // Sign a JWT and store the user ID and challenge on it for later retrieval
  const jwt = await new SignJWT(<ChallengeJWT> { 
    sub: userId,
    userName: body.userName,
    challenge_b64: challenge_b64
   })
   .setExpirationTime('5m')
   .setProtectedHeader({ alg: 'ES256' })
   .sign(ServerKP.privateKey);

  // Send the registration options and signed JWT to the user
  // All ArrayBuffers need to be encoded into b64 for transport
  res.json(<RegistrationStartResponse> {
    'token': jwt,
    'options': {
      ...opts,
      challenge: challenge_b64
    }
  });
  return;
}