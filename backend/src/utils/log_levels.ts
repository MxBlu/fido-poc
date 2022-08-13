/** 
 * Log levels for use with {@link Logger}
 */
export enum LogLevel {
  /** If set on a logger, ignore all log messages */
  IGNORE = -1,
  /** Error messages */
  ERROR,
  /** Warning messages */
  WARN,
  /** Informational messages */
  INFO,
  /** Debugging messages */
  DEBUG,
  /** Verbose debugging messages */
  TRACE
}

