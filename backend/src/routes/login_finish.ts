import assert from "assert";
import { Request, Response } from "express";
import { AssertionResult } from "fido2-lib";
import { jwtVerify } from "jose";
import { ORIGIN } from "../constants.js";
import { ChallengeJWT, Credential, UserData } from "../models.js";
import { Fido2, ServerKP, Users } from "../runtime_globals.js";
import { ab2str } from "../utils/ab2str.js";
import { Logger } from "../utils/logger.js";

/** Module logger */
const logger = new Logger("LoginFinish");

/** Request body for /login/finish */
interface LoginFinishBody {
  token: string;
  result: AssertionResult;
}

/** 
 * Login finish route, provided a LoginFinishBody 
 * Returns 200 with a login challenge on sucess, 403 on authentication failure, 400 on bad request 
*/
export async function loginFinishHandle(req: Request, res: Response): Promise<void> {
  // Parse and validate request body
  let body: LoginFinishBody = null;
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

  try {
    // Find the credentials that the challenge was signed by
    let user: UserData = null;
    let cred: Credential = null;
    if (jwt.userName != null) {
      logger.info(`Login attempt against username: ${jwt.userName}`);

      // If a username is present, look for the credentials under that user
      user = Users.get(jwt.userName);
      cred = user.credentials.filter(c => c.credentialId == body.result.rawId)[0];
    } else {
      logger.info(`Resident key login attempt`);
      // If no username is present, look through all the users for a credential that matches
      for (const curUser of Users.values()) {
        const potentialCreds = curUser.credentials.filter(c => c.credentialId == body.result.rawId);
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
      logger.warn(`Matching credentials not found: ${ab2str(body.result.rawId)}`);
      res.status(403).json({ 'error': 'Unknown credentials' });
      return;
    }

    // Validate the assertion against the challenge
    const assertionRes = await Fido2.assertionResult(body.result, {
      challenge: jwt.challenge,
      origin: ORIGIN,
      factor: 'first',
      publicKey: cred.publicKey,
      prevCounter: cred.counter,
      userHandle: ab2str(cred.credentialId)
    });

    // Update the counter on the credential
    cred.counter = assertionRes.authnrData.get("counter");
    
    logger.warn(`Login successful for username: ${user.userName}`);

    // Return success, along with the user object
    res.json({ 
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