import { Buffer } from 'node:buffer';
import { describe, it, expect } from 'vitest';
import {
  readInt8,
  readUint8,
  readInt16BE,
  readInt16LE,
  readUint16BE,
  readUint16LE,
  readInt32BE,
  readInt32LE,
  readUint32BE,
  readUint32LE,
  readBigInt64BE,
  readBigInt64LE,
  readBigUint64BE,
  readBigUint64LE,
} from '../utils/byte-readers';
import { BufferOutOfBoundsError } from '../errors';

describe('Byte Reader Utilities', () => {
  describe('readInt8', () => {
    it('should read a signed 8-bit integer', () => {
      const buf = Buffer.from([0x00, 0x7f, 0x80, 0xff]);
      expect(readInt8(buf, 0)).toBe(0);
      expect(readInt8(buf, 1)).toBe(127);
      expect(readInt8(buf, 2)).toBe(-128);
      expect(readInt8(buf, 3)).toBe(-1);
    });

    it('should throw BufferOutOfBoundsError for invalid offset', () => {
      const buf = Buffer.from([0x01]);
      expect(() => readInt8(buf, -1)).toThrow(BufferOutOfBoundsError);
      expect(() => readInt8(buf, 1)).toThrow(BufferOutOfBoundsError);
      expect(() => readInt8(buf, 10)).toThrow(BufferOutOfBoundsError);
    });
  });

  describe('readUint8', () => {
    it('should read an unsigned 8-bit integer', () => {
      const buf = Buffer.from([0x00, 0x7f, 0x80, 0xff]);
      expect(readUint8(buf, 0)).toBe(0);
      expect(readUint8(buf, 1)).toBe(127);
      expect(readUint8(buf, 2)).toBe(128);
      expect(readUint8(buf, 3)).toBe(255);
    });

    it('should throw BufferOutOfBoundsError for invalid offset', () => {
      const buf = Buffer.from([0x01]);
      expect(() => readUint8(buf, -1)).toThrow(BufferOutOfBoundsError);
      expect(() => readUint8(buf, 1)).toThrow(BufferOutOfBoundsError);
      expect(() => readUint8(buf, 10)).toThrow(BufferOutOfBoundsError);
    });
  });

  describe('readInt16BE', () => {
    it('should read a signed 16-bit integer in big-endian', () => {
      const buf = Buffer.from([0x00, 0x01, 0x7f, 0xff, 0x80, 0x00, 0xff, 0xfe]);
      expect(readInt16BE(buf, 0)).toBe(1);
      expect(readInt16BE(buf, 2)).toBe(32767);
      expect(readInt16BE(buf, 4)).toBe(-32768);
      expect(readInt16BE(buf, 6)).toBe(-2);
    });

    it('should throw BufferOutOfBoundsError for invalid offset or insufficient length', () => {
      const buf = Buffer.from([0x01, 0x02]);
      expect(() => readInt16BE(buf, -1)).toThrow(BufferOutOfBoundsError);
      expect(() => readInt16BE(buf, 1)).toThrow(BufferOutOfBoundsError); // Not enough bytes
      expect(() => readInt16BE(buf, 2)).toThrow(BufferOutOfBoundsError);
      const shortBuf = Buffer.from([0x01]);
      expect(() => readInt16BE(shortBuf, 0)).toThrow(BufferOutOfBoundsError);
    });
  });

  describe('readInt16LE', () => {
    it('should read a signed 16-bit integer in little-endian', () => {
      const buf = Buffer.from([0x01, 0x00, 0xff, 0x7f, 0x00, 0x80, 0xfe, 0xff]);
      expect(readInt16LE(buf, 0)).toBe(1);
      expect(readInt16LE(buf, 2)).toBe(32767);
      expect(readInt16LE(buf, 4)).toBe(-32768);
      expect(readInt16LE(buf, 6)).toBe(-2);
    });

    it('should throw BufferOutOfBoundsError for invalid offset or insufficient length', () => {
      const buf = Buffer.from([0x01, 0x02]);
      expect(() => readInt16LE(buf, -1)).toThrow(BufferOutOfBoundsError);
      expect(() => readInt16LE(buf, 1)).toThrow(BufferOutOfBoundsError);
      expect(() => readInt16LE(buf, 2)).toThrow(BufferOutOfBoundsError);
      const shortBuf = Buffer.from([0x01]);
      expect(() => readInt16LE(shortBuf, 0)).toThrow(BufferOutOfBoundsError);
    });
  });

  describe('readUint16BE', () => {
    it('should read an unsigned 16-bit integer in big-endian', () => {
      const buf = Buffer.from([0x00, 0x01, 0x7f, 0xff, 0x80, 0x00, 0xff, 0xff]);
      expect(readUint16BE(buf, 0)).toBe(1);
      expect(readUint16BE(buf, 2)).toBe(32767);
      expect(readUint16BE(buf, 4)).toBe(32768);
      expect(readUint16BE(buf, 6)).toBe(65535);
    });

    it('should throw BufferOutOfBoundsError for invalid offset or insufficient length', () => {
      const buf = Buffer.from([0x01, 0x02]);
      expect(() => readUint16BE(buf, -1)).toThrow(BufferOutOfBoundsError);
      expect(() => readUint16BE(buf, 1)).toThrow(BufferOutOfBoundsError);
      expect(() => readUint16BE(buf, 2)).toThrow(BufferOutOfBoundsError);
      const shortBuf = Buffer.from([0x01]);
      expect(() => readUint16BE(shortBuf, 0)).toThrow(BufferOutOfBoundsError);
    });
  });

  describe('readUint16LE', () => {
    it('should read an unsigned 16-bit integer in little-endian', () => {
      const buf = Buffer.from([0x01, 0x00, 0xff, 0x7f, 0x00, 0x80, 0xff, 0xff]);
      expect(readUint16LE(buf, 0)).toBe(1);
      expect(readUint16LE(buf, 2)).toBe(32767);
      expect(readUint16LE(buf, 4)).toBe(32768);
      expect(readUint16LE(buf, 6)).toBe(65535);
    });

    it('should throw BufferOutOfBoundsError for invalid offset or insufficient length', () => {
      const buf = Buffer.from([0x01, 0x02]);
      expect(() => readUint16LE(buf, -1)).toThrow(BufferOutOfBoundsError);
      expect(() => readUint16LE(buf, 1)).toThrow(BufferOutOfBoundsError);
      expect(() => readUint16LE(buf, 2)).toThrow(BufferOutOfBoundsError);
      const shortBuf = Buffer.from([0x01]);
      expect(() => readUint16LE(shortBuf, 0)).toThrow(BufferOutOfBoundsError);
    });
  });

  describe('readInt32BE', () => {
    it('should read a signed 32-bit integer in big-endian', () => {
      const buf = Buffer.from([0x00, 0x00, 0x00, 0x01, 0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfe]);
      expect(readInt32BE(buf, 0)).toBe(1);
      expect(readInt32BE(buf, 4)).toBe(2147483647);
      expect(readInt32BE(buf, 8)).toBe(-2147483648);
      expect(readInt32BE(buf, 12)).toBe(-2);
    });

    it('should throw BufferOutOfBoundsError for invalid offset or insufficient length', () => {
      const buf = Buffer.from([0x01, 0x02, 0x03, 0x04]);
      expect(() => readInt32BE(buf, -1)).toThrow(BufferOutOfBoundsError);
      expect(() => readInt32BE(buf, 1)).toThrow(BufferOutOfBoundsError); // Not enough bytes
      expect(() => readInt32BE(buf, 4)).toThrow(BufferOutOfBoundsError);
      const shortBuf = Buffer.from([0x01, 0x02, 0x03]);
      expect(() => readInt32BE(shortBuf, 0)).toThrow(BufferOutOfBoundsError);
    });
  });

  describe('readInt32LE', () => {
    it('should read a signed 32-bit integer in little-endian', () => {
      const buf = Buffer.from([0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x80, 0xfe, 0xff, 0xff, 0xff]);
      expect(readInt32LE(buf, 0)).toBe(1);
      expect(readInt32LE(buf, 4)).toBe(2147483647);
      expect(readInt32LE(buf, 8)).toBe(-2147483648);
      expect(readInt32LE(buf, 12)).toBe(-2);
    });

    it('should throw BufferOutOfBoundsError for invalid offset or insufficient length', () => {
      const buf = Buffer.from([0x01, 0x02, 0x03, 0x04]);
      expect(() => readInt32LE(buf, -1)).toThrow(BufferOutOfBoundsError);
      expect(() => readInt32LE(buf, 1)).toThrow(BufferOutOfBoundsError);
      expect(() => readInt32LE(buf, 4)).toThrow(BufferOutOfBoundsError);
      const shortBuf = Buffer.from([0x01, 0x02, 0x03]);
      expect(() => readInt32LE(shortBuf, 0)).toThrow(BufferOutOfBoundsError);
    });
  });

  describe('readUint32BE', () => {
    it('should read an unsigned 32-bit integer in big-endian', () => {
      const buf = Buffer.from([0x00, 0x00, 0x00, 0x01, 0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff]);
      expect(readUint32BE(buf, 0)).toBe(1);
      expect(readUint32BE(buf, 4)).toBe(2147483647);
      expect(readUint32BE(buf, 8)).toBe(2147483648);
      expect(readUint32BE(buf, 12)).toBe(4294967295);
    });

    it('should throw BufferOutOfBoundsError for invalid offset or insufficient length', () => {
      const buf = Buffer.from([0x01, 0x02, 0x03, 0x04]);
      expect(() => readUint32BE(buf, -1)).toThrow(BufferOutOfBoundsError);
      expect(() => readUint32BE(buf, 1)).toThrow(BufferOutOfBoundsError);
      expect(() => readUint32BE(buf, 4)).toThrow(BufferOutOfBoundsError);
      const shortBuf = Buffer.from([0x01, 0x02, 0x03]);
      expect(() => readUint32BE(shortBuf, 0)).toThrow(BufferOutOfBoundsError);
    });
  });

  describe('readUint32LE', () => {
    it('should read an unsigned 32-bit integer in little-endian', () => {
      const buf = Buffer.from([0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0xff]);
      expect(readUint32LE(buf, 0)).toBe(1);
      expect(readUint32LE(buf, 4)).toBe(2147483647);
      expect(readUint32LE(buf, 8)).toBe(2147483648);
      expect(readUint32LE(buf, 12)).toBe(4294967295);
    });

    it('should throw BufferOutOfBoundsError for invalid offset or insufficient length', () => {
      const buf = Buffer.from([0x01, 0x02, 0x03, 0x04]);
      expect(() => readUint32LE(buf, -1)).toThrow(BufferOutOfBoundsError);
      expect(() => readUint32LE(buf, 1)).toThrow(BufferOutOfBoundsError);
      expect(() => readUint32LE(buf, 4)).toThrow(BufferOutOfBoundsError);
      const shortBuf = Buffer.from([0x01, 0x02, 0x03]);
      expect(() => readUint32LE(shortBuf, 0)).toThrow(BufferOutOfBoundsError);
    });
  });

  describe('readBigInt64BE', () => {
    it('should read a signed 64-bit integer in big-endian', () => {
      const buf = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe]);
      expect(readBigInt64BE(buf, 0)).toBe(1n);
      expect(readBigInt64BE(buf, 8)).toBe(9223372036854775807n);
      expect(readBigInt64BE(buf, 16)).toBe(-9223372036854775808n);
      expect(readBigInt64BE(buf, 24)).toBe(-2n);
    });

    it('should throw BufferOutOfBoundsError for invalid offset or insufficient length', () => {
      const buf = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
      expect(() => readBigInt64BE(buf, -1)).toThrow(BufferOutOfBoundsError);
      expect(() => readBigInt64BE(buf, 1)).toThrow(BufferOutOfBoundsError); // Not enough bytes
      expect(() => readBigInt64BE(buf, 8)).toThrow(BufferOutOfBoundsError);
      const shortBuf = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
      expect(() => readBigInt64BE(shortBuf, 0)).toThrow(BufferOutOfBoundsError);
    });
  });

  describe('readBigInt64LE', () => {
    it('should read a signed 64-bit integer in little-endian', () => {
      const buf = Buffer.from([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
      expect(readBigInt64LE(buf, 0)).toBe(1n);
      expect(readBigInt64LE(buf, 8)).toBe(9223372036854775807n);
      expect(readBigInt64LE(buf, 16)).toBe(-9223372036854775808n);
      expect(readBigInt64LE(buf, 24)).toBe(-2n);
    });

    it('should throw BufferOutOfBoundsError for invalid offset or insufficient length', () => {
      const buf = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
      expect(() => readBigInt64LE(buf, -1)).toThrow(BufferOutOfBoundsError);
      expect(() => readBigInt64LE(buf, 1)).toThrow(BufferOutOfBoundsError);
      expect(() => readBigInt64LE(buf, 8)).toThrow(BufferOutOfBoundsError);
      const shortBuf = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
      expect(() => readBigInt64LE(shortBuf, 0)).toThrow(BufferOutOfBoundsError);
    });
  });

  describe('readBigUint64BE', () => {
    it('should read an unsigned 64-bit integer in big-endian', () => {
      const buf = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
      expect(readBigUint64BE(buf, 0)).toBe(1n);
      expect(readBigUint64BE(buf, 8)).toBe(9223372036854775807n);
      expect(readBigUint64BE(buf, 16)).toBe(9223372036854775808n);
      expect(readBigUint64BE(buf, 24)).toBe(18446744073709551615n);
    });

    it('should throw BufferOutOfBoundsError for invalid offset or insufficient length', () => {
      const buf = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
      expect(() => readBigUint64BE(buf, -1)).toThrow(BufferOutOfBoundsError);
      expect(() => readBigUint64BE(buf, 1)).toThrow(BufferOutOfBoundsError);
      expect(() => readBigUint64BE(buf, 8)).toThrow(BufferOutOfBoundsError);
      const shortBuf = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
      expect(() => readBigUint64BE(shortBuf, 0)).toThrow(BufferOutOfBoundsError);
    });
  });

  describe('readBigUint64LE', () => {
    it('should read an unsigned 64-bit integer in little-endian', () => {
      const buf = Buffer.from([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
      expect(readBigUint64LE(buf, 0)).toBe(1n);
      expect(readBigUint64LE(buf, 8)).toBe(9223372036854775807n);
      expect(readBigUint64LE(buf, 16)).toBe(9223372036854775808n);
      expect(readBigUint64LE(buf, 24)).toBe(18446744073709551615n);
    });

    it('should throw BufferOutOfBoundsError for invalid offset or insufficient length', () => {
      const buf = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
      expect(() => readBigUint64LE(buf, -1)).toThrow(BufferOutOfBoundsError);
      expect(() => readBigUint64LE(buf, 1)).toThrow(BufferOutOfBoundsError);
      expect(() => readBigUint64LE(buf, 8)).toThrow(BufferOutOfBoundsError);
      const shortBuf = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
      expect(() => readBigUint64LE(shortBuf, 0)).toThrow(BufferOutOfBoundsError);
    });
  });
});