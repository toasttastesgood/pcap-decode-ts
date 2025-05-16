import { describe, it, expect, beforeEach } from 'vitest';
import { ICMPv4Decoder } from '../../../decode/icmpv4/icmpv4-decoder';
import { ICMPv4Layer } from '../../../decode/icmpv4/icmpv4-layer';
import { BufferOutOfBoundsError } from '../../../errors';
import { DecoderOutputLayer } from '../../../decode/decoder';

describe('ICMPv4Decoder', () => {
  let decoder: ICMPv4Decoder;

  beforeEach(() => {
    decoder = new ICMPv4Decoder();
  });

  it('should have the correct protocolName', () => {
    expect(decoder.protocolName).toBe('ICMPv4');
  });

  it('should return null for nextProtocolType', () => {
    const mockLayerData: ICMPv4Layer = {
      type: 8,
      code: 0,
      checksum: 0x1234,
      data: Buffer.from([0x01, 0x02, 0x03, 0x04]),
    };
    expect(decoder.nextProtocolType(mockLayerData)).toBeNull();
  });

  describe('decode', () => {
    it('should throw BufferOutOfBoundsError if buffer is too small', () => {
      const buffer = Buffer.from([0x08, 0x00, 0x01]); // 3 bytes, too small
      expect(() => decoder.decode(buffer)).toThrow(BufferOutOfBoundsError);
      expect(() => decoder.decode(buffer)).toThrow(
        'Buffer too small for ICMPv4 header. Expected at least 4 bytes, got 3.',
      );
    });

    it('should correctly decode an Echo Request packet (Type 8, Code 0)', () => {
      // ICMP Echo Request: Type 8, Code 0, Checksum (example), Identifier (2 bytes), Sequence (2 bytes), Data
      const identifier = Buffer.from([0x12, 0x34]);
      const sequence = Buffer.from([0x56, 0x78]);
      const icmpData = Buffer.from('abcdefghijklmnopqrstuvwxyz');
      const fullData = Buffer.concat([identifier, sequence, icmpData]);

      // For simplicity, checksum is not validated here, so a placeholder is fine.
      // Real checksum would be calculated over Type, Code, Identifier, Sequence, Data.
      // Type (1) + Code (1) + Checksum (2) + Data (fullData.length)
      const buffer = Buffer.concat([Buffer.from([0x08, 0x00, 0x00, 0x00]), fullData]);
      // Manually set a dummy checksum for now.
      // A real checksum calculation would involve the entire ICMP message.
      // For this test, we'll use a placeholder and verify the other fields.
      // Let's assume a simple checksum for testing purposes.
      // For an actual packet, this would be calculated.
      buffer.writeUInt16BE(0xabcd, 2); // Dummy checksum

      const decoded = decoder.decode(buffer) as DecoderOutputLayer<ICMPv4Layer>;

      expect(decoded).not.toBeNull();
      expect(decoded.protocolName).toBe('ICMPv4');
      expect(decoded.headerLength).toBe(buffer.length);
      expect(decoded.payload.length).toBe(0);

      const layerData = decoded.data;
      expect(layerData.type).toBe(8);
      expect(layerData.code).toBe(0);
      expect(layerData.checksum).toBe(0xabcd);
      expect(layerData.data).toEqual(fullData);
    });

    it('should correctly decode an Echo Reply packet (Type 0, Code 0)', () => {
      const identifier = Buffer.from([0xaa, 0xbb]);
      const sequence = Buffer.from([0xcc, 0xdd]);
      const icmpData = Buffer.from('zyxwutsrqponmlkjihgfedcba');
      const fullData = Buffer.concat([identifier, sequence, icmpData]);
      const buffer = Buffer.concat([Buffer.from([0x00, 0x00, 0x12, 0x34]), fullData]); // Dummy checksum 0x1234
      buffer.writeUInt16BE(0xef01, 2); // Dummy checksum

      const decoded = decoder.decode(buffer) as DecoderOutputLayer<ICMPv4Layer>;

      expect(decoded).not.toBeNull();
      expect(decoded.protocolName).toBe('ICMPv4');
      expect(decoded.headerLength).toBe(buffer.length);
      expect(decoded.payload.length).toBe(0);

      const layerData = decoded.data;
      expect(layerData.type).toBe(0);
      expect(layerData.code).toBe(0);
      expect(layerData.checksum).toBe(0xef01);
      expect(layerData.data).toEqual(fullData);
    });

    it('should correctly decode a Destination Unreachable (Type 3, Code 1 - Host Unreachable)', () => {
      // Type 3, Code 1, Checksum, Unused (4 bytes), IP Header + 8 bytes of original datagram
      const unused = Buffer.from([0x00, 0x00, 0x00, 0x00]);
      const originalIpHeader = Buffer.from([
        0x45,
        0x00,
        0x00,
        0x3c,
        0x1c,
        0x46,
        0x40,
        0x00,
        0x40,
        0x06,
        0x00,
        0x00, // IP Header (20 bytes)
        0xac,
        0x10,
        0x0a,
        0x01, // Source IP: 172.16.10.1
        0xac,
        0x10,
        0x0a,
        0x02, // Destination IP: 172.16.10.2
      ]);
      const originalData = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // 8 bytes of original data
      const fullData = Buffer.concat([unused, originalIpHeader, originalData]);
      const buffer = Buffer.concat([Buffer.from([0x03, 0x01, 0xfe, 0xdc]), fullData]); // Dummy checksum 0xfedc

      const decoded = decoder.decode(buffer) as DecoderOutputLayer<ICMPv4Layer>;

      expect(decoded).not.toBeNull();
      expect(decoded.protocolName).toBe('ICMPv4');
      expect(decoded.headerLength).toBe(buffer.length);
      expect(decoded.payload.length).toBe(0);

      const layerData = decoded.data;
      expect(layerData.type).toBe(3);
      expect(layerData.code).toBe(1);
      expect(layerData.checksum).toBe(0xfedc);
      expect(layerData.data).toEqual(fullData);
    });

    it('should correctly decode a Time Exceeded (Type 11, Code 0 - TTL exceeded in transit)', () => {
      // Type 11, Code 0, Checksum, Unused (4 bytes), IP Header + 8 bytes of original datagram
      const unused = Buffer.from([0x00, 0x00, 0x00, 0x00]);
      const originalIpHeader = Buffer.from([
        0x45,
        0x00,
        0x00,
        0x28, // IP version, IHL, Type of Service, Total Length
        0x12,
        0x34,
        0x00,
        0x00, // Identification, Flags, Fragment Offset
        0x80,
        0x11,
        0x00,
        0x00, // TTL, Protocol, Header Checksum
        0xc0,
        0xa8,
        0x01,
        0x01, // Source IP: 192.168.1.1
        0xc0,
        0xa8,
        0x01,
        0x64, // Destination IP: 192.168.1.100
      ]);
      const originalData = Buffer.from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]); // 8 bytes
      const fullData = Buffer.concat([unused, originalIpHeader, originalData]);
      const buffer = Buffer.concat([Buffer.from([0x0b, 0x00, 0xab, 0xcd]), fullData]); // Dummy checksum 0xabcd

      const decoded = decoder.decode(buffer) as DecoderOutputLayer<ICMPv4Layer>;

      expect(decoded).not.toBeNull();
      expect(decoded.protocolName).toBe('ICMPv4');
      expect(decoded.headerLength).toBe(buffer.length);
      expect(decoded.payload.length).toBe(0);

      const layerData = decoded.data;
      expect(layerData.type).toBe(11);
      expect(layerData.code).toBe(0);
      expect(layerData.checksum).toBe(0xabcd);
      expect(layerData.data).toEqual(fullData);
    });

    // Add more tests for other ICMP types/codes as needed.
    // Add tests for checksum validation if/when implemented.
  });
});
