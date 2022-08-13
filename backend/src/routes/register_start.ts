import assert from "assert";
import { Request, Response } from "express";
import { SignJWT } from "jose";
import { Fido2, ServerKP, Users } from "../runtime_globals.js";
import { Logger } from "../utils/logger.js";

/** Module logger */
const logger = new Logger("RegistrationStart");

/** Request body for /register/start */
interface RegistrationStartBody {
  displayName: string;
  name: string;
}

/** 
 * Registration start route, provided a RegistrationStartBody 
 * 
 * Returns a 200 with registration details on success, 400 on bad request
*/
export async function registerStartHandle(req: Request, res: Response): Promise<void> {
  // Parse and validate request body
  let body: RegistrationStartBody = null;
  try {
    body = JSON.parse(req.body);
    assert(typeof body.displayName === 'string');
    assert(typeof body.name === 'string');
  } catch (e) {
    const error = <Error> e;
    logger.error(error.message);
    console.error(error.stack);
    res.status(400).json({ 'error': 'Invalid request' });
    return;
  }

  // Check username availability
  if (Users.has(body.name)) {
    logger.warn(`Username in use: ${body.name}`);
    res.status(400).json({ 'error': 'Username in use' });
    return;
  }
  
  logger.info(`Registration request for username: ${body.name}`);

  // Generate a user ID
  const userId = crypto.randomUUID();

  // Generate registration options
  const opts = await Fido2.attestationOptions();
  opts.user.id = userId;
  opts.user.displayName = body.displayName;
  opts.user.name = body.name;

  // Persist user details to user data
  Users.set(body.name, {
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
   .sign(ServerKP.privateKey);

  // Send the registration options and signed JWT to the user
  res.json({
    'token': jwt,
    'options': opts
  });
  return;
}