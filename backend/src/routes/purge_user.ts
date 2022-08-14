import assert from "assert";
import { Request, Response } from "express";
import { Users } from "../runtime_globals.js";
import { Logger } from "../utils/logger.js";

/** Module logger */
const logger = new Logger("PurgeUser");

/** Request body for /user/delete */
interface PurgeUserRequest {
  userName: string;
}

/** Response body for /user/delete */
interface PurgeUserResponse {
  error?: string;
  status?: string;
}

/** 
 * Delete a user from the system
 * 
 * Returns a 200 on success, 400 on bad request
*/
export function purgeUserHandle(req: Request, res: Response): void {
  // Parse and validate request body
  const body: PurgeUserRequest = req.body ?? {};
  try {
    assert(typeof body.userName === 'string', "Username is not present or is not a string");
  } catch (e) {
    const error = <Error> e;
    logger.warn(error.message);
    res.status(400).json(<PurgeUserResponse> { 'error': error.message });
    return;
  }
  
  // Delete the user from the Users map
  Users.delete(body.userName);
  logger.info(`Purged user: ${body.userName}`);

  // Return success
  res.json(<PurgeUserResponse> { 'status': 'ok' });
  return;
}