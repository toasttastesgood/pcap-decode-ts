import { Buffer } from 'node:buffer';
import { describe, it, expect } from 'vitest';
import { formatIPv4, formatIPv6 } from '../utils/ip-formatters';

describe('IP Address Formatters', () => {
  describe('formatIPv4', () => {
    it('should format a valid IPv4 address from a buffer', () => {
      const buf = Buffer.from([192, 168, 1, 1]);
      expect(formatIPv4(buf)).toBe('192.168.1.1');
    });

    it('should format a valid IPv4 address from a buffer with an offset', () => {
      const buf = Buffer.from([0x00, 0x00, 192, 168, 1, 1]);
      expect(formatIPv4(buf, 2)).toBe('192.168.1.1');
    });

    it('should handle all zero IPv4 address', () => {
      const buf = Buffer.from([0, 0, 0, 0]);
      expect(formatIPv4(buf)).toBe('0.0.0.0');
    });

    it('should handle all 255 IPv4 address', () => {
      const buf = Buffer.from([255, 255, 255, 255]);
      expect(formatIPv4(buf)).toBe('255.255.255.255');
    });

    it('should throw an error if the buffer is too short', () => {
      const buf = Buffer.from([192, 168, 1]);
      expect(() => formatIPv4(buf)).toThrow('Buffer too short to contain an IPv4 address.');
    });

    it('should throw an error if the offset makes the buffer too short', () => {
      const buf = Buffer.from([0x00, 192, 168, 1, 1]);
      expect(() => formatIPv4(buf, 2)).toThrow('Buffer too short to contain an IPv4 address.');
    });
  });

  describe('formatIPv6', () => {
    it('should format a valid IPv6 address from a buffer', () => {
      const buf = Buffer.from([
        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
        0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
      ]);
      expect(formatIPv6(buf)).toBe('2001:db8:85a3:0:0:8a2e:370:7334');
    });

    it('should format a valid IPv6 address from a buffer with an offset', () => {
      const buf = Buffer.from([
        0x00, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
        0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
      ]);
      expect(formatIPv6(buf, 2)).toBe('2001:db8:85a3:0:0:8a2e:370:7334');
    });

    it('should handle an all-zero IPv6 address (uncompressed)', () => {
      const buf = Buffer.alloc(16); // All zeros
      expect(formatIPv6(buf)).toBe('0:0:0:0:0:0:0:0');
    });

    it('should handle an IPv6 address with leading zeros in segments', () => {
      const buf = Buffer.from([
        0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
        0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08,
      ]);
      expect(formatIPv6(buf)).toBe('1:2:3:4:5:6:7:8');
    });

    it('should handle an IPv6 address with FFFF segments', () => {
        const buf = Buffer.from([
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ]);
        expect(formatIPv6(buf)).toBe('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');
    });


    it('should throw an error if the buffer is too short', () => {
      const buf = Buffer.alloc(15); // One byte too short
      expect(() => formatIPv6(buf)).toThrow('Buffer too short to contain an IPv6 address.');
    });

    it('should throw an error if the offset makes the buffer too short', () => {
      const buf = Buffer.alloc(17);
      expect(() => formatIPv6(buf, 2)).toThrow('Buffer too short to contain an IPv6 address.');
    });
  });
});