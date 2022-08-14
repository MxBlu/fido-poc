import assert from "assert";
import * as base64buffer from 'base64-arraybuffer';
import { Request, Response } from "express";
import { AttestationResult } from "fido2-lib";
import { jwtVerify } from "jose";
import { ORIGIN } from "../constants.js";
import { AttestationResultWireFormat, ChallengeJWT, FIDO2Credential } from "../models.js";
import { Fido2, ServerKP, Users } from "../runtime_globals.js";
import { Logger } from "../utils/logger.js";

/** Module logger */
const logger = new Logger("RegistrationFinish");

/** Request body for /register/finish */
interface RegistrationFinishRequest {
  token: string;
  result: AttestationResultWireFormat; // TODO: Maybe switch to PublicKeyCredential
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

  // Decode base 64 data back to Array Buffers
  const result: AttestationResult = {
    ...body.result,
    id: base64buffer.decode(body.result.id),
    rawId: base64buffer.decode(body.result.rawId),
    response: {
      attestationObject: body.result.response.attestationObject,
      clientDataJSON: body.result.response.clientDataJSON
    }
  }

  try {
    // Validate the attestation against the challenge
    const attestationRes = await Fido2.attestationResult(result, {
      challenge: jwt.challenge_b64,
      factor: 'first', // First factor forces on UV, ensure not set to 'discouraged' in Fido2Lib options
      origin: ORIGIN
    });

    // Fetch the user object
    const user = Users.get(jwt.userName);

    // Update the user ID and append these credentials to the list
    user.userHandle = jwt.sub;
    const credential: FIDO2Credential = {
      counter: attestationRes.authnrData.get('counter'),
      credentialId_b64: base64buffer.encode(attestationRes.authnrData.get('credId')),
      publicKey: attestationRes.authnrData.get('credentialPublicKeyPem')
    };
    user.credentials = [ credential ];
    
    logger.info(`New credential registered: ${credential.credentialId_b64}`);

    // Return success
    res.json(<RegistrationFinishResponse> { 'status': 'ok' });
    return;
  } catch (e) {
    // Clean up user since registration failed
    Users.delete(jwt.userName);
    // Log error
    const error = <Error> e;
    logger.warn(`Attestation failed: ${error.message}`);
    console.error(error.stack);
    res.status(403).json(<RegistrationFinishResponse> { 'error': 'Attestation failed' });
    return;
  }
}