import assert from "assert";
import { Request, Response } from "express";
import { AttestationResult } from "fido2-lib";
import { jwtVerify } from "jose";
import { ORIGIN } from "../constants.js";
import { ChallengeJWT, Credential } from "../models.js";
import { Fido2, ServerKP, Users } from "../runtime_globals.js";
import { ab2str } from "../utils/ab2str.js";
import { Logger } from "../utils/logger.js";

/** Module logger */
const logger = new Logger("RegistrationFinish");

/** Request body for /register/finish */
interface RegistrationFinishBody {
  token: string;
  result: AttestationResult;
}

/** 
 * Registration finish route, provided a RegistrationFinishBody 
 * Returns 200 on success, 403 on attestation failure, 400 on bad request
*/
export async function registerFinishHandle(req: Request, res: Response): Promise<void> {
  // Parse and validate request body
  let body: RegistrationFinishBody = null;
  try {
    body = JSON.parse(req.body);
    assert(typeof body.token === 'string');
    assert(body.result !== null || body.result !== undefined);
  } catch (e) {
    const error = <Error> e;
    logger.error(error.message);
    console.error(error.stack);
    res.status(400).json({ 'error': 'Invalid request' });
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
    const credential: Credential = {
      counter: attestationRes.authnrData.get('counter'),
      credentialId: attestationRes.authnrData.get('credId'),
      publicKey: attestationRes.authnrData.get('credentialPublicKeyPem')
    };
    user.credentials.push(credential);
    
    logger.info(`New credential registered: ${ab2str(credential.credentialId)}`);

    // Return success
    res.json({ 'status': 'ok' });
    return;
  } catch (e) {
    const error = <Error> e;
    logger.warn(`Attestation failed: ${error.message}`);
    console.error(error.stack);
    res.status(403).json({ 'error': 'Attestation failed' });
    return;
  }
}