import assert from "assert";
import * as base64buffer from 'base64-arraybuffer';
import { Request, Response } from "express";
import { AssertionResult } from "fido2-lib";
import { jwtVerify } from "jose";
import { ORIGIN } from "../constants.js";
import { AssertionResultWireFormat, ChallengeJWT, FIDO2Credential, UserData } from "../models.js";
import { Fido2, ServerKP, Users } from "../runtime_globals.js";
import { Logger } from "../utils/logger.js";

/** Module logger */
const logger = new Logger("LoginFinish");

/** Request body for /login/finish */
interface LoginFinishRequest {
  token: string;
  result: AssertionResultWireFormat;
}

/** Response body for /login/finish */
interface LoginFinishResponse {
  error?: string;
  status?: string;
  user?: {
    userName: string;
    displayName: string;
  }
}

/** 
 * Login finish route, provided a LoginFinishBody 
 * Returns 200 with a login challenge on sucess, 403 on authentication failure, 400 on bad request 
*/
export async function loginFinishHandle(req: Request, res: Response): Promise<void> {
  // Parse and validate request body
  const body: LoginFinishRequest = req.body ?? {};
  try {
    assert(typeof body.token === 'string', 'Token is not present or is not a string');
    assert(body.result !== null || body.result !== undefined, 'Result is not present');
  } catch (e) {
    const error = <Error> e;
    logger.warn(error.message);
    res.status(400).json(<LoginFinishResponse> { 'error': error.message });
    return;
  }

  // Verify and decode the JWT
  const jwtDecode = await jwtVerify(body.token, ServerKP.publicKey);
  const jwt = <ChallengeJWT> jwtDecode.payload;

  try {
    // Find the credentials that the challenge was signed by
    let user: UserData = null;
    let cred: FIDO2Credential = null;
    if (jwt.userName != null) {
      logger.info(`Login attempt against username: ${jwt.userName}`);

      // If a username is present, look for the credentials under that user
      user = Users.get(jwt.userName);
      cred = user.credentials.filter(c => c.credentialId_b64 == body.result.rawId)[0];
    } else {
      logger.info(`Resident key login attempt`);
      // If no username is present, look through all the users for a credential that matches
      for (const curUser of Users.values()) {
        const potentialCreds = curUser.credentials.filter(c => c.credentialId_b64 == body.result.rawId);
        if (potentialCreds.length > 0) {
          logger.info(`Matching user found: ${curUser.userName}`);
          // Keep track of the user and matching credential
          user = curUser;
          cred = potentialCreds[0];
          break;
        }
      }
    }

    // If we couldn't find a matching set of credentials, throw a 403
    if (cred == null) {
      logger.warn(`Matching credentials not found: ${body.result.rawId}`);
      res.status(403).json(<LoginFinishResponse> { 'error': 'Unknown credentials' });
      return;
    }

    // Decode all the base 64 encoded data to ArrayBuffers
    const result: AssertionResult = {
      ...body.result,
      id: base64buffer.decode(body.result.id),
      rawId: base64buffer.decode(body.result.rawId),
      response: {
        ...body.result.response,
        authenticatorData: base64buffer.decode(body.result.response.authenticatorData)
      }
    }

    // Validate the assertion against the challenge
    const assertionRes = await Fido2.assertionResult(result, {
      challenge: jwt.challenge_b64,
      origin: ORIGIN,
      factor: 'first', // First factor forces on UV, ensure not set to 'discouraged' in Fido2Lib options
      publicKey: cred.publicKey,
      prevCounter: cred.counter,
      userHandle: base64buffer.encode(new TextEncoder().encode(user.userHandle))
    });

    // Update the counter on the credential
    cred.counter = assertionRes.authnrData.get("counter");
    
    logger.warn(`Login successful for username: ${user.userName}`);

    // Return success, along with the user object
    res.json(<LoginFinishResponse> { 
      'status': 'ok', 
      'user': {
        'userName': user.userName,
        'displayName': user.displayName
      } 
    });
    return;
  } catch (e) {
    const error = <Error> e;
    logger.warn(`Assertion failed: ${error.message}`);
    console.error(error.stack);
    res.status(403).json({ 'error': 'Assertion failed' });
    return;
  }
}