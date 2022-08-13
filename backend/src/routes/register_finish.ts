import assert from "assert";
import { Request, Response } from "express";
import { AttestationResult } from "fido2-lib";
import { jwtVerify } from "jose";
import { ORIGIN } from "../constants.js";
import { ChallengeJWT, FIDO2Credential } from "../models.js";
import { Fido2, ServerKP, Users } from "../runtime_globals.js";
import { ab2str } from "../utils/ab2str.js";
import { Logger } from "../utils/logger.js";

/** Module logger */
const logger = new Logger("RegistrationFinish");

/** Request body for /register/finish */
interface RegistrationFinishRequest {
  token: string;
  result: AttestationResult; // TODO: Maybe switch to PublicKeyCredential
}

/** Response body for /register/finish */
interface RegistrationFinishResponse {
  error?: string;
  status?: string;
}

/** 
 * Registration finish route, provided a RegistrationFinishBody 
 * Returns 200 on success, 403 on attestation failure, 400 on bad request
*/
export async function registerFinishHandle(req: Request, res: Response): Promise<void> {
  // Parse and validate request body
  const body: RegistrationFinishRequest = req.body ?? {};
  try {
    assert(typeof body.token === 'string', "Token is not present or is not a string");
    assert(body.result !== null || body.result !== undefined, "Body is not present");
  } catch (e) {
    const error = <Error> e;
    logger.warn(error.message);
    res.status(400).json(<RegistrationFinishResponse> { 'error': error.message });
    return;
  }

  // Verify and decode the JWT
  const jwtDecode = await jwtVerify(body.token, ServerKP.publicKey);
  const jwt = <ChallengeJWT> jwtDecode.payload;
  
  logger.info(`Registration finish for username: ${jwt.userName}`);

  try {
    // Validate the attestation against the challenge
    const attestationRes = await Fido2.attestationResult(body.result, { 
      challenge: jwt.challenge,
      factor: 'first',
      origin: ORIGIN
    });

    // Fetch the user object
    const user = Users.get(jwt.userName);

    // Update the user ID and append these credentials to the list
    user.userHandle = jwt.sub;
    const credential: FIDO2Credential = {
      counter: attestationRes.authnrData.get('counter'),
      credentialId: attestationRes.authnrData.get('credId'),
      publicKey: attestationRes.authnrData.get('credentialPublicKeyPem')
    };
    user.credentials.push(credential);
    
    logger.info(`New credential registered: ${ab2str(credential.credentialId)}`);

    // Return success
    res.json(<RegistrationFinishResponse> { 'status': 'ok' });
    return;
  } catch (e) {
    const error = <Error> e;
    logger.warn(`Attestation failed: ${error.message}`);
    console.error(error.stack);
    res.status(403).json(<RegistrationFinishResponse> { 'error': 'Attestation failed' });
    return;
  }
}