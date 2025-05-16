import { describe, it, expect } from 'vitest';
import {
  PcapError,
  PcapParsingError,
  PcapDecodingError,
  BufferOutOfBoundsError,
  InvalidFileFormatError,
  UnsupportedLinktypeError,
} from '../errors';

describe('Custom Error Classes', () => {
  describe('PcapError', () => {
    it('should create an instance of PcapError', () => {
      const error = new PcapError('Test PcapError');
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(PcapError);
      expect(error.name).toBe('PcapError');
      expect(error.message).toBe('Test PcapError');
    });
  });

  describe('PcapParsingError', () => {
    it('should create an instance of PcapParsingError', () => {
      const error = new PcapParsingError('Test PcapParsingError');
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(PcapError);
      expect(error).toBeInstanceOf(PcapParsingError);
      expect(error.name).toBe('PcapParsingError');
      expect(error.message).toBe('Test PcapParsingError');
    });
  });

  describe('PcapDecodingError', () => {
    it('should create an instance of PcapDecodingError', () => {
      const error = new PcapDecodingError('Test PcapDecodingError');
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(PcapError);
      expect(error).toBeInstanceOf(PcapDecodingError);
      expect(error.name).toBe('PcapDecodingError');
      expect(error.message).toBe('Test PcapDecodingError');
    });
  });

  describe('BufferOutOfBoundsError', () => {
    it('should create an instance of BufferOutOfBoundsError with a default message', () => {
      const error = new BufferOutOfBoundsError();
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(PcapError);
      expect(error).toBeInstanceOf(PcapParsingError);
      expect(error).toBeInstanceOf(BufferOutOfBoundsError);
      expect(error.name).toBe('BufferOutOfBoundsError');
      expect(error.message).toBe('Attempted to read beyond buffer bounds');
    });

    it('should create an instance of BufferOutOfBoundsError with a custom message', () => {
      const error = new BufferOutOfBoundsError('Custom out of bounds message');
      expect(error).toBeInstanceOf(BufferOutOfBoundsError);
      expect(error.name).toBe('BufferOutOfBoundsError');
      expect(error.message).toBe('Custom out of bounds message');
    });
  });

  describe('InvalidFileFormatError', () => {
    it('should create an instance of InvalidFileFormatError', () => {
      const error = new InvalidFileFormatError('Test InvalidFileFormatError');
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(PcapError);
      expect(error).toBeInstanceOf(PcapParsingError);
      expect(error).toBeInstanceOf(InvalidFileFormatError);
      expect(error.name).toBe('InvalidFileFormatError');
      expect(error.message).toBe('Test InvalidFileFormatError');
    });
  });

  describe('UnsupportedLinktypeError', () => {
    it('should create an instance of UnsupportedLinktypeError', () => {
      const error = new UnsupportedLinktypeError(123);
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(PcapError);
      expect(error).toBeInstanceOf(PcapDecodingError);
      expect(error).toBeInstanceOf(UnsupportedLinktypeError);
      expect(error.name).toBe('UnsupportedLinktypeError');
      expect(error.message).toBe('Unsupported linktype: 123');
    });
  });
});
