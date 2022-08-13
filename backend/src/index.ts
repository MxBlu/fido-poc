import cors from 'cors';
import Express, { NextFunction, Request, Response } from 'express';
import { PORT } from './constants.js';
import { loginFinishHandle } from './routes/login_finish.js';
import { loginStartHandle } from './routes/login_start.js';
import { registerFinishHandle } from './routes/register_finish.js';
import { registerStartHandle } from './routes/register_start';
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
 */
function logError(err: Error, req: Request, res: Response): void {
  // Log the error and return a 500
  logger.error(`Error processing request: ${req.path} - ${err.name}: ${err.message}`);
  res.sendStatus(500);
}

const app = Express();

/** Simple echoing route handler for testing */
app.get('/echo', (_, res): void => {
  res.send('echo');
});

// CORS handler
app.use(cors({
  origin: true, // TODO: Make origin strict in production
  // credentials: true
}));
// Request logger
app.use(logRequest);

// Add API routes
app.post('/register/start', runAsync(registerStartHandle));
app.post('/register/finish', runAsync(registerFinishHandle));
app.post('/login/start', runAsync(loginStartHandle));
app.post('/login/finish', runAsync(loginFinishHandle));

// Error handler
app.use(logError);

// Start server
app.listen(PORT, () => { console.log(`Listening on port ${PORT}`) });