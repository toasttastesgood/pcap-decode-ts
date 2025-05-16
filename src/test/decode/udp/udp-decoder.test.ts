import { describe, it, expect, beforeEach } from 'vitest';
import { UDPDecoder, UDPLayer } from '../../../decode/udp/udp-decoder';
import { BufferOutOfBoundsError, PcapDecodingError } from '../../../errors';
import { DecoderOutputLayer } from '../../../decode/decoder';

describe('UDPDecoder', () => {
  let decoder: UDPDecoder;

  beforeEach(() => {
    decoder = new UDPDecoder();
  });

  it('should have the correct protocolName', () => {
    expect(decoder.protocolName).toBe('UDP');
  });

  describe('decode', () => {
    it('should correctly decode a valid UDP packet', () => {
      // Sample UDP packet:
      // Source Port: 12345 (0x3039)
      // Destination Port: 80 (0x0050)
      // Length: 12 (header + 4 bytes data) (0x000C)
      // Checksum: 0xABCD
      // Data: "TEST" (0x54455354)
      const buffer = Buffer.from([
        0x30,
        0x39, // Source Port
        0x00,
        0x50, // Destination Port
        0x00,
        0x0c, // Length
        0xab,
        0xcd, // Checksum
        0x54,
        0x45,
        0x53,
        0x54, // Payload "TEST"
      ]);

      const decoded = decoder.decode(buffer) as DecoderOutputLayer<UDPLayer>;

      expect(decoded).not.toBeNull();
      expect(decoded.protocolName).toBe('UDP');
      expect(decoded.headerLength).toBe(8);
      expect(decoded.data.sourcePort).toBe(12345);
      expect(decoded.data.destinationPort).toBe(80);
      expect(decoded.data.length).toBe(12);
      expect(decoded.data.checksum).toBe(0xabcd);
      expect(decoded.payload.toString('ascii')).toBe('TEST');
      expect(decoded.payload.length).toBe(4);
    });

    it('should throw BufferOutOfBoundsError if buffer is too small for header', () => {
      const buffer = Buffer.from([0x30, 0x39, 0x00, 0x50, 0x00]); // 5 bytes, less than 8
      expect(() => decoder.decode(buffer)).toThrow(BufferOutOfBoundsError);
      expect(() => decoder.decode(buffer)).toThrow(
        'Buffer too small for UDP header. Expected at least 8 bytes, got 5.',
      );
    });

    it('should throw BufferOutOfBoundsError if length field indicates size larger than buffer', () => {
      const buffer = Buffer.from([
        0x30,
        0x39, // Source Port
        0x00,
        0x50, // Destination Port
        0x00,
        0xff, // Length (255)
        0xab,
        0xcd, // Checksum
        // Only 8 bytes in buffer, but length field says 255
      ]);
      expect(() => decoder.decode(buffer)).toThrow(BufferOutOfBoundsError);
      expect(() => decoder.decode(buffer)).toThrow(
        'Buffer too small for declared UDP packet length. Expected 255 bytes (from UDP length field at offset 4), got 8.',
      );
    });

    it('should throw PcapDecodingError if UDP length field is less than 8', () => {
      const buffer = Buffer.from([
        0x30,
        0x39, // Source Port
        0x00,
        0x50, // Destination Port
        0x00,
        0x07, // Length (7) - Invalid
        0xab,
        0xcd, // Checksum
      ]);
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow(
        'Invalid UDP length field (7) at offset 4. Value is less than minimum UDP header size (8).',
      );
    });

    it('should correctly decode a UDP packet with no payload', () => {
      // Source Port: 54321 (0xD431)
      // Destination Port: 123 (0x007B)
      // Length: 8 (header only) (0x0008)
      // Checksum: 0x1234
      const buffer = Buffer.from([
        0xd4,
        0x31, // Source Port
        0x00,
        0x7b, // Destination Port
        0x00,
        0x08, // Length
        0x12,
        0x34, // Checksum
      ]);

      const decoded = decoder.decode(buffer) as DecoderOutputLayer<UDPLayer>;

      expect(decoded).not.toBeNull();
      expect(decoded.protocolName).toBe('UDP');
      expect(decoded.headerLength).toBe(8);
      expect(decoded.data.sourcePort).toBe(54321);
      expect(decoded.data.destinationPort).toBe(123);
      expect(decoded.data.length).toBe(8);
      expect(decoded.data.checksum).toBe(0x1234);
      expect(decoded.payload.length).toBe(0);
    });
  });

  describe('nextProtocolType', () => {
    it('should return null', () => {
      const dummyData: UDPLayer = {
        sourcePort: 1,
        destinationPort: 2,
        length: 8,
        checksum: 0,
      };
      expect(decoder.nextProtocolType(dummyData)).toBeNull();
    });
  });
});
