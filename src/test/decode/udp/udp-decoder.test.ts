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

    it('should correctly decode a UDP packet with a zero checksum', () => {
      // Source Port: 12345 (0x3039)
      // Destination Port: 80 (0x0050)
      // Length: 10 (header + 2 bytes data) (0x000A)
      // Checksum: 0x0000 (zero checksum)
      // Data: "HI" (0x4849)
      const buffer = Buffer.from([
        0x30,
        0x39, // Source Port
        0x00,
        0x50, // Destination Port
        0x00,
        0x0a, // Length
        0x00,
        0x00, // Checksum (zero)
        0x48,
        0x49, // Payload "HI"
      ]);

      const decoded = decoder.decode(buffer) as DecoderOutputLayer<UDPLayer>;

      expect(decoded).not.toBeNull();
      expect(decoded.protocolName).toBe('UDP');
      expect(decoded.headerLength).toBe(8);
      expect(decoded.data.sourcePort).toBe(12345);
      expect(decoded.data.destinationPort).toBe(80);
      expect(decoded.data.length).toBe(10);
      expect(decoded.data.checksum).toBe(0x0000); // Verify zero checksum
      expect(decoded.payload.toString('ascii')).toBe('HI');
      expect(decoded.payload.length).toBe(2);
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

  it('should correctly decode a UDP packet with 0xFFFF checksum and larger payload', () => {
    // Source Port: 65000 (0xFD28)
    // Destination Port: 65001 (0xFD29)
    // Length: 18 (header + 10 bytes data) (0x0012)
    // Checksum: 0xFFFF
    // Data: "HELLODATA!" (0x48454c4c4f4441544121)
    const buffer = Buffer.from([
      0xfd,
      0x28, // Source Port
      0xfd,
      0x29, // Destination Port
      0x00,
      0x12, // Length (18)
      0xff,
      0xff, // Checksum
      0x48,
      0x45,
      0x4c,
      0x4c,
      0x4f,
      0x44,
      0x41,
      0x54,
      0x41,
      0x21, // Payload "HELLODATA!"
    ]);

    const decoded = decoder.decode(buffer) as DecoderOutputLayer<UDPLayer>;

    expect(decoded).not.toBeNull();
    expect(decoded.protocolName).toBe('UDP');
    expect(decoded.headerLength).toBe(8);
    expect(decoded.data.sourcePort).toBe(65000);
    expect(decoded.data.destinationPort).toBe(65001);
    expect(decoded.data.length).toBe(18);
    expect(decoded.data.checksum).toBe(0xffff);
    expect(decoded.payload.toString('ascii')).toBe('HELLODATA!');
    expect(decoded.payload.length).toBe(10);
  });

  it('should correctly decode UDP packets with min/max port numbers', () => {
    // Min ports (0), Max ports (65535)
    // Source Port: 0 (0x0000)
    // Destination Port: 65535 (0xFFFF)
    // Length: 9 (header + 1 byte data) (0x0009)
    // Checksum: 0x1234
    // Data: "A" (0x41)
    const bufferMinMaxPorts = Buffer.from([
      0x00,
      0x00, // Source Port (0)
      0xff,
      0xff, // Destination Port (65535)
      0x00,
      0x09, // Length
      0x12,
      0x34, // Checksum
      0x41, // Payload "A"
    ]);

    let decoded = decoder.decode(bufferMinMaxPorts) as DecoderOutputLayer<UDPLayer>;
    expect(decoded.data.sourcePort).toBe(0);
    expect(decoded.data.destinationPort).toBe(65535);
    expect(decoded.data.length).toBe(9);
    expect(decoded.payload.length).toBe(1);

    // Max ports (65535), Min ports (0)
    // Source Port: 65535 (0xFFFF)
    // Destination Port: 0 (0x0000)
    // Length: 8 (header only) (0x0008)
    // Checksum: 0x4321
    const bufferMaxMinPorts = Buffer.from([
      0xff,
      0xff, // Source Port (65535)
      0x00,
      0x00, // Destination Port (0)
      0x00,
      0x08, // Length
      0x43,
      0x21, // Checksum
    ]);

    decoded = decoder.decode(bufferMaxMinPorts) as DecoderOutputLayer<UDPLayer>;
    expect(decoded.data.sourcePort).toBe(65535);
    expect(decoded.data.destinationPort).toBe(0);
    expect(decoded.data.length).toBe(8);
    expect(decoded.payload.length).toBe(0);
  });
});
