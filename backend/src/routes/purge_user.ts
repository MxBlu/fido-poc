import assert from "assert";
import { Request, Response } from "express";
import { Users } from "../runtime_globals.js";
import { Logger } from "../utils/logger.js";

/** Module logger */
const logger = new Logger("PurgeUser");

/** Request body for /register/start */
interface PurgeUserBody {
  userName: string;
}

/** 
 * Delete a user from the system
 * 
 * Returns a 200 on success, 400 on bad request
*/
export function purgeUserHandle(req: Request, res: Response): void {
  // Parse and validate request body
  let body: PurgeUserBody = null;
  try {
    body = JSON.parse(req.body);
    assert(typeof body.userName === 'string');
  } catch (e) {
    const error = <Error> e;
    logger.error(error.message);
    console.error(error.stack);
    res.status(400).json({ 'error': 'Invalid request' });
    return;
  }
  
  Users.delete(body.userName);
  logger.info(`Purged user: ${body.userName}`);

  // Return success
  res.json({ 'status': 'ok' });
  return;
}