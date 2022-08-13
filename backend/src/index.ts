import cors from 'cors';
import Express, { NextFunction, Request, Response } from 'express';
import { PORT } from './constants.js';
import { loginFinishHandle } from './routes/login_finish.js';
import { loginStartHandle } from './routes/login_start.js';
import { registerFinishHandle } from './routes/register_finish.js';
import { registerStartHandle } from './routes/register_start.js';
import { Logger } from './utils/logger.js';

/**
 * General FIDO2 info:
 * 
 * Platform authenticators ('platform') - Uses Windows Hello
 * Roaming authenticators ('cross-platform') - Uses FIDO2 key
 * 
 * TODO: Test resident keys
 */

const logger = new Logger("FidoPOC");

type AsyncExpressHandlerFunction = (req: Request, res: Response, next: NextFunction) => Promise<void>;
type ExpressHandlerFunction = (req: Request, res: Response, next: NextFunction) => void;

/**
 * Wrap an async route handler in a catch to forward errors to `next()`
 * @param handler Async route handler function
 * @returns Wrapped route handler function
 */
function runAsync(handler: AsyncExpressHandlerFunction): ExpressHandlerFunction {
  return function (req, res, next) {
    handler(req, res, next)
      .catch(next);
  };
}

/**
 * Log requests on arrival
 * @param req Express Request
 * @param res Express Response
 * @param next Express NextFunction
 */
function logRequest(req: Request, res: Response, next: NextFunction): void {
  // Log request paths with IPs
  logger.info(`Request: ${req.path} - ${req.ip}`);
  next();
}

/**
 * Log errors and return a 500
 * @param err Error
 * @param req Express Request
 * @param res Express Response
 * @param _next Express NextFunction (unused)
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function logError(err: Error, req: Request, res: Response, _next: NextFunction): void {
  // Log the error and return a 500
  logger.error(`Error processing request: ${req.path} - ${err.name}: ${err.message}`);
  res.sendStatus(500);
}

/**
 * Log a warning and return a 404 on an unknown route
 * @param req Express Request
 * @param res Express Response
 * @param _next Express NextFunction (unused)
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function unknownRoute(req: Request, res: Response, _next: NextFunction): void {
  // If we don't have a specific handler for the route, send a 404
  logger.warn(`Unknown route accessed: ${req.path}`);
  res.sendStatus(404);
}

const app = Express();

// CORS handler
app.use(cors({
  origin: true, // TODO: Make origin strict in production
  // credentials: true
}));
// Request logger
app.use(logRequest);

// Add testing route
app.get('/echo', (_, res): void => {
  res.send('echo');
});

// Add API routes
app.post('/register/start', runAsync(registerStartHandle));
app.post('/register/finish', runAsync(registerFinishHandle));
app.post('/login/start', runAsync(loginStartHandle));
app.post('/login/finish', runAsync(loginFinishHandle));

// Unknown route handler
app.use(unknownRoute);
// Error handler
app.use(logError);

// Start server
app.listen(PORT, () => { logger.info(`Listening on port ${PORT}`) });