export enum LogLevel {
  NONE = 0,
  ERROR = 1,
  WARN = 2,
  INFO = 3,
  DEBUG = 4,
}

let currentLogLevel: LogLevel = LogLevel.WARN; // Default log level

/**
 * Sets the current logging level for the library.
 * @param level The desired log level.
 */
export function setLogLevel(level: LogLevel): void {
  currentLogLevel = level;
}

/**
 * Gets the current logging level.
 * @returns The current LogLevel.
 */
export function getLogLevel(): LogLevel {
  return currentLogLevel;
}

/**
 * Logs an error message if the current log level is ERROR or higher.
 * @param message The message to log.
 * @param optionalParams Any additional parameters to log.
 */
export function logError(message?: unknown, ...optionalParams: unknown[]): void {
  if (currentLogLevel >= LogLevel.ERROR) {
    console.error(`[PCAP-ERROR] ${message}`, ...optionalParams);
  }
}

/**
 * Logs a warning message if the current log level is WARN or higher.
 * @param message The message to log.
 * @param optionalParams Any additional parameters to log.
 */
export function logWarning(message?: unknown, ...optionalParams: unknown[]): void {
  if (currentLogLevel >= LogLevel.WARN) {
    console.warn(`[PCAP-WARN] ${message}`, ...optionalParams);
  }
}

/**
 * Logs an informational message if the current log level is INFO or higher.
 * @param message The message to log.
 * @param optionalParams Any additional parameters to log.
 */
export function logInfo(message?: unknown, ...optionalParams: unknown[]): void {
  if (currentLogLevel >= LogLevel.INFO) {
    console.info(`[PCAP-INFO] ${message}`, ...optionalParams);
  }
}

/**
 * Logs a debug message if the current log level is DEBUG or higher.
 * @param message The message to log.
 * @param optionalParams Any additional parameters to log.
 */
export function logDebug(message?: unknown, ...optionalParams: unknown[]): void {
  if (currentLogLevel >= LogLevel.DEBUG) {
    console.debug(`[PCAP-DEBUG] ${message}`, ...optionalParams);
  }
}
