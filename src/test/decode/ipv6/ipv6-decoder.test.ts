import { describe, it, expect } from 'vitest';
import { IPv6Decoder } from '../../../decode/ipv6/ipv6-decoder';
import { IPv6Layer } from '../../../decode/ipv6/ipv6-layer';
import { BufferOutOfBoundsError, PcapDecodingError } from '../../../errors';
import { DecoderOutputLayer } from '../../../decode/decoder';

describe('IPv6Decoder', () => {
  const decoder = new IPv6Decoder();

  // Helper to create a minimal valid IPv6 header buffer
  const createIPv6Header = (
    payloadLength: number,
    nextHeader: number,
    sourceIp = '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
    destinationIp = '2001:0db8:85a3:0000:0000:8a2e:0370:7335',
    version = 6,
    trafficClass = 0,
    flowLabel = 0,
    hopLimit = 64,
  ): Buffer => {
    const buffer = Buffer.alloc(40);
    // Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
    buffer.writeUInt32BE((version << 28) | (trafficClass << 20) | flowLabel, 0);
    // Payload Length (16 bits)
    buffer.writeUInt16BE(payloadLength, 4);
    // Next Header (8 bits)
    buffer.writeUInt8(nextHeader, 6);
    // Hop Limit (8 bits)
    buffer.writeUInt8(hopLimit, 7);

    // Source IP (128 bits / 16 bytes)
    const srcIpParts = sourceIp.split(':').map((part) => parseInt(part, 16));
    let offset = 8;
    for (let i = 0; i < 8; i++) {
      buffer.writeUInt16BE(srcIpParts[i] || 0, offset);
      offset += 2;
    }

    // Destination IP (128 bits / 16 bytes)
    const destIpParts = destinationIp.split(':').map((part) => parseInt(part, 16));
    offset = 24;
    for (let i = 0; i < 8; i++) {
      buffer.writeUInt16BE(destIpParts[i] || 0, offset);
      offset += 2;
    }
    return buffer;
  };

  it('should have the correct protocolName', () => {
    expect(decoder.protocolName).toBe('IPv6');
  });

  it('should decode a valid IPv6 packet with TCP payload', () => {
    const payload = Buffer.from('test payload');
    const header = createIPv6Header(payload.length, 6); // 6 for TCP
    const packet = Buffer.concat([header, payload]);

    const decoded = decoder.decode(packet) as DecoderOutputLayer<IPv6Layer>;

    expect(decoded).toBeDefined();
    expect(decoded.protocolName).toBe('IPv6');
    expect(decoded.headerLength).toBe(40);
    expect(decoded.data.version).toBe(6);
    expect(decoded.data.trafficClass).toBe(0);
    expect(decoded.data.flowLabel).toBe(0);
    expect(decoded.data.payloadLength).toBe(payload.length);
    expect(decoded.data.nextHeader).toBe(6); // TCP
    expect(decoded.data.hopLimit).toBe(64);
    expect(decoded.data.sourceIp).toBe('2001:db8:85a3:0:0:8a2e:370:7334');
    expect(decoded.data.destinationIp).toBe('2001:db8:85a3:0:0:8a2e:370:7335');
    expect(decoded.payload.equals(payload)).toBe(true);
    expect(decoder.nextProtocolType(decoded.data)).toBe(6);
  });

  it('should decode a valid IPv6 packet with UDP payload', () => {
    const payload = Buffer.from('another payload');
    const header = createIPv6Header(payload.length, 17); // 17 for UDP
    const packet = Buffer.concat([header, payload]);

    const decoded = decoder.decode(packet) as DecoderOutputLayer<IPv6Layer>;

    expect(decoded).toBeDefined();
    expect(decoded.data.nextHeader).toBe(17); // UDP
    expect(decoded.data.payloadLength).toBe(payload.length);
    expect(decoded.payload.equals(payload)).toBe(true);
    expect(decoder.nextProtocolType(decoded.data)).toBe(17);
  });

  it('should decode a valid IPv6 packet with ICMPv6 payload', () => {
    const payload = Buffer.from('icmpv6 data');
    const header = createIPv6Header(payload.length, 58); // 58 for ICMPv6
    const packet = Buffer.concat([header, payload]);

    const decoded = decoder.decode(packet) as DecoderOutputLayer<IPv6Layer>;

    expect(decoded).toBeDefined();
    expect(decoded.data.nextHeader).toBe(58); // ICMPv6
    expect(decoded.data.payloadLength).toBe(payload.length);
    expect(decoded.payload.equals(payload)).toBe(true);
    expect(decoder.nextProtocolType(decoded.data)).toBe(58);
  });

  it('should correctly extract all header fields', () => {
    const payload = Buffer.from([0x01, 0x02]);
    const sourceIp = 'fe80:0000:0000:0000:0202:b3ff:fe1e:8329';
    const destinationIp = 'ff02:0000:0000:0000:0000:0000:0000:0001';
    const header = createIPv6Header(
      payload.length,
      17, // UDP
      sourceIp,
      destinationIp,
      6, // version
      5, // traffic class
      12345, // flow label
      128, // hop limit
    );
    const packet = Buffer.concat([header, payload]);
    const decoded = decoder.decode(packet) as DecoderOutputLayer<IPv6Layer>;

    expect(decoded.data.version).toBe(6);
    expect(decoded.data.trafficClass).toBe(5);
    expect(decoded.data.flowLabel).toBe(12345);
    expect(decoded.data.payloadLength).toBe(payload.length);
    expect(decoded.data.nextHeader).toBe(17);
    expect(decoded.data.hopLimit).toBe(128);
    expect(decoded.data.sourceIp).toBe('fe80:0:0:0:202:b3ff:fe1e:8329');
    expect(decoded.data.destinationIp).toBe('ff02:0:0:0:0:0:0:1');
  });

  it('should throw BufferOutOfBoundsError if buffer is too small for header', () => {
    const tooSmallBuffer = Buffer.alloc(39); // Less than 40 bytes
    expect(() => decoder.decode(tooSmallBuffer)).toThrow(BufferOutOfBoundsError);
    expect(() => decoder.decode(tooSmallBuffer)).toThrow(
      'Buffer too small for IPv6 header at offset 0. Expected 40 bytes, got 39.',
    );
  });

  it('should throw BufferOutOfBoundsError if buffer is smaller than declared payload length', () => {
    const payloadLength = 100;
    const actualPayload = Buffer.alloc(50); // Smaller than declared
    const header = createIPv6Header(payloadLength, 6);
    const packet = Buffer.concat([header, actualPayload]);

    expect(() => decoder.decode(packet)).toThrow(BufferOutOfBoundsError);
    expect(() => decoder.decode(packet)).toThrow(
      'Buffer too small for declared IPv6 payload length (100 bytes) at offset 40. Buffer remaining: 50 bytes.',
    );
  });

  it('should throw PcapDecodingError for invalid IPv6 version', () => {
    const header = createIPv6Header(10, 6, undefined, undefined, 4); // Invalid version 4
    const packet = Buffer.concat([header, Buffer.alloc(10)]);
    expect(() => decoder.decode(packet)).toThrow(PcapDecodingError);
    expect(() => decoder.decode(packet)).toThrow(
      'Invalid IPv6 version at offset 0: 4. Expected 6.',
    );
  });

  it('should handle offset correctly', () => {
    const payload = Buffer.from('offset payload');
    const header = createIPv6Header(payload.length, 6);
    const prefix = Buffer.from([0xca, 0xfe]);
    const packet = Buffer.concat([prefix, header, payload]);
    const offset = prefix.length;

    const decoded = decoder.decode(packet, offset) as DecoderOutputLayer<IPv6Layer>;

    expect(decoded).toBeDefined();
    expect(decoded.protocolName).toBe('IPv6');
    expect(decoded.headerLength).toBe(40);
    expect(decoded.data.version).toBe(6);
    expect(decoded.data.payloadLength).toBe(payload.length);
    expect(decoded.data.nextHeader).toBe(6);
    expect(decoded.payload.equals(payload)).toBe(true);
    expect(decoder.nextProtocolType(decoded.data)).toBe(6);
  });
});
