import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  LogLevel,
  setLogLevel,
  getLogLevel,
  logError,
  logWarning,
  logInfo,
  logDebug,
} from '../../utils/logger';

describe('Logger Utilities', () => {
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let warnSpy: ReturnType<typeof vi.spyOn>;
  let infoSpy: ReturnType<typeof vi.spyOn>;
  let debugSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    // Reset log level to default before each test
    setLogLevel(LogLevel.WARN);

    // Spy on console methods
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    infoSpy = vi.spyOn(console, 'info').mockImplementation(() => {});
    debugSpy = vi.spyOn(console, 'debug').mockImplementation(() => {});
  });

  afterEach(() => {
    // Restore original console methods
    errorSpy.mockRestore();
    warnSpy.mockRestore();
    infoSpy.mockRestore();
    debugSpy.mockRestore();
  });

  describe('setLogLevel and getLogLevel', () => {
    it('should set and get the log level correctly', () => {
      expect(getLogLevel()).toBe(LogLevel.WARN); // Default

      setLogLevel(LogLevel.ERROR);
      expect(getLogLevel()).toBe(LogLevel.ERROR);

      setLogLevel(LogLevel.INFO);
      expect(getLogLevel()).toBe(LogLevel.INFO);

      setLogLevel(LogLevel.DEBUG);
      expect(getLogLevel()).toBe(LogLevel.DEBUG);

      setLogLevel(LogLevel.NONE);
      expect(getLogLevel()).toBe(LogLevel.NONE);
    });
  });

  describe('logError', () => {
    it('should log an error message when logLevel is ERROR or higher', () => {
      setLogLevel(LogLevel.ERROR);
      logError('Test error');
      expect(errorSpy).toHaveBeenCalledWith('[PCAP-ERROR] Test error');

      setLogLevel(LogLevel.WARN); // ERROR < WARN
      logError('Test error 2');
      expect(errorSpy).toHaveBeenCalledWith('[PCAP-ERROR] Test error 2');
      expect(errorSpy).toHaveBeenCalledTimes(2);
    });

    it('should not log an error message when logLevel is NONE', () => {
      setLogLevel(LogLevel.NONE);
      logError('Test error');
      expect(errorSpy).not.toHaveBeenCalled();
    });

    it('should log with optional parameters', () => {
      setLogLevel(LogLevel.ERROR);
      logError('Error with params:', 1, { data: 'test' });
      expect(errorSpy).toHaveBeenCalledWith('[PCAP-ERROR] Error with params:', 1, { data: 'test' });
    });
  });

  describe('logWarning', () => {
    it('should log a warning message when logLevel is WARN or higher', () => {
      setLogLevel(LogLevel.WARN);
      logWarning('Test warning');
      expect(warnSpy).toHaveBeenCalledWith('[PCAP-WARN] Test warning');

      setLogLevel(LogLevel.INFO); // WARN < INFO
      logWarning('Test warning 2');
      expect(warnSpy).toHaveBeenCalledWith('[PCAP-WARN] Test warning 2');
      expect(warnSpy).toHaveBeenCalledTimes(2);
    });

    it('should not log a warning message when logLevel is below WARN (e.g., ERROR, NONE)', () => {
      setLogLevel(LogLevel.ERROR);
      logWarning('Test warning');
      expect(warnSpy).not.toHaveBeenCalled();

      setLogLevel(LogLevel.NONE);
      logWarning('Test warning 2');
      expect(warnSpy).not.toHaveBeenCalled();
    });
  });

  describe('logInfo', () => {
    it('should log an info message when logLevel is INFO or higher', () => {
      setLogLevel(LogLevel.INFO);
      logInfo('Test info');
      expect(infoSpy).toHaveBeenCalledWith('[PCAP-INFO] Test info');

      setLogLevel(LogLevel.DEBUG); // INFO < DEBUG
      logInfo('Test info 2');
      expect(infoSpy).toHaveBeenCalledWith('[PCAP-INFO] Test info 2');
      expect(infoSpy).toHaveBeenCalledTimes(2);
    });

    it('should not log an info message when logLevel is below INFO (e.g., WARN, ERROR, NONE)', () => {
      setLogLevel(LogLevel.WARN);
      logInfo('Test info');
      expect(infoSpy).not.toHaveBeenCalled();

      setLogLevel(LogLevel.ERROR);
      logInfo('Test info 2');
      expect(infoSpy).not.toHaveBeenCalled();

      setLogLevel(LogLevel.NONE);
      logInfo('Test info 3');
      expect(infoSpy).not.toHaveBeenCalled();
    });
  });

  describe('logDebug', () => {
    it('should log a debug message only when logLevel is DEBUG', () => {
      setLogLevel(LogLevel.DEBUG);
      logDebug('Test debug');
      expect(debugSpy).toHaveBeenCalledWith('[PCAP-DEBUG] Test debug');
    });

    it('should not log a debug message when logLevel is below DEBUG', () => {
      setLogLevel(LogLevel.INFO);
      logDebug('Test debug');
      expect(debugSpy).not.toHaveBeenCalled();

      setLogLevel(LogLevel.WARN);
      logDebug('Test debug 2');
      expect(debugSpy).not.toHaveBeenCalled();

      setLogLevel(LogLevel.ERROR);
      logDebug('Test debug 3');
      expect(debugSpy).not.toHaveBeenCalled();

      setLogLevel(LogLevel.NONE);
      logDebug('Test debug 4');
      expect(debugSpy).not.toHaveBeenCalled();
    });
  });

  describe('Default LogLevel (WARN)', () => {
    // beforeEach resets to WARN
    it('should log ERROR messages by default', () => {
      logError('Default error');
      expect(errorSpy).toHaveBeenCalledWith('[PCAP-ERROR] Default error');
    });

    it('should log WARN messages by default', () => {
      logWarning('Default warning');
      expect(warnSpy).toHaveBeenCalledWith('[PCAP-WARN] Default warning');
    });

    it('should NOT log INFO messages by default', () => {
      logInfo('Default info');
      expect(infoSpy).not.toHaveBeenCalled();
    });

    it('should NOT log DEBUG messages by default', () => {
      logDebug('Default debug');
      expect(debugSpy).not.toHaveBeenCalled();
    });
  });
});