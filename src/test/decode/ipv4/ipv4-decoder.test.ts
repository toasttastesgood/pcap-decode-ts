import { Buffer } from 'buffer';
import { describe, it, expect, vi } from 'vitest';
import { IPv4Decoder } from '../../../decode/ipv4/ipv4-decoder';
import { IPv4Layer } from '../../../decode/ipv4/ipv4-layer';
import { BufferOutOfBoundsError, PcapDecodingError } from '../../../errors';

describe('IPv4Decoder', () => {
  const decoder = new IPv4Decoder();

  // Minimal valid IPv4 header (20 bytes), no options, protocol TCP (6)
  // Version: 4, IHL: 5 (20 bytes)
  // DSCP: 0, ECN: 0
  // Total Length: 20 (header only, no payload for this minimal test)
  // Identification: 0x1234
  // Flags: 0, Fragment Offset: 0
  // TTL: 64
  // Protocol: 6 (TCP)
  // Header Checksum: 0xABCD (dummy value, validation not strictly enforced in decoder yet)
  // Source IP: 192.168.0.1
  // Destination IP: 10.0.0.1
  const minimalValidIPv4Buffer = Buffer.from([
    0x45, // Version 4, IHL 5
    0x00, // DSCP 0, ECN 0
    0x00,
    0x14, // Total Length 20
    0x12,
    0x34, // Identification
    0x00,
    0x00, // Flags 0, Fragment Offset 0
    0x40, // TTL 64
    0x06, // Protocol TCP (6)
    0xab,
    0xcd, // Header Checksum (dummy)
    192,
    168,
    0,
    1, // Source IP: 192.168.0.1
    10,
    0,
    0,
    1, // Destination IP: 10.0.0.1
  ]);

  // IPv4 header with options (IHL 6 -> 24 bytes), protocol UDP (17)
  // Options: 4 bytes of NOP (0x01) for simplicity
  // Total Length: 24 (header only)
  const ipv4WithOptionsMenuBuffer = Buffer.from([
    0x46, // Version 4, IHL 6 (24 bytes)
    0x00, // DSCP 0, ECN 0
    0x00,
    0x18, // Total Length 24
    0x56,
    0x78, // Identification
    0x40,
    0x00, // Flags: Don't Fragment, Fragment Offset 0
    0x80, // TTL 128
    0x11, // Protocol UDP (17)
    0xdc,
    0xba, // Header Checksum (dummy)
    172,
    16,
    0,
    1, // Source IP: 172.16.0.1
    172,
    16,
    0,
    2, // Destination IP: 172.16.0.2
    0x01,
    0x01,
    0x01,
    0x01, // Options: 4x NOP
  ]);

  // IPv4 header, protocol ICMP (1)
  // Total Length: 28 (header + 8 byte ICMP dummy payload)
  const ipv4IcmpBuffer = Buffer.from([
    0x45, // Version 4, IHL 5
    0x00, // DSCP 0, ECN 0
    0x00,
    0x1c, // Total Length 28 (20 header + 8 payload)
    0xab,
    0xcd, // Identification
    0x00,
    0x00, // Flags 0, Fragment Offset 0
    0x20, // TTL 32
    0x01, // Protocol ICMP (1)
    0xef,
    0xbe, // Header Checksum (dummy)
    10,
    1,
    1,
    10, // Source IP: 10.1.1.10
    10,
    1,
    1,
    20, // Destination IP: 10.1.1.20
    // Dummy ICMP payload (8 bytes)
    0x08,
    0x00,
    0x12,
    0x34,
    0x56,
    0x78,
    0x9a,
    0xbc,
  ]);

  it('should have the correct protocolName', () => {
    expect(decoder.protocolName).toBe('IPv4');
  });

  describe('Minimal Valid IPv4 Packet (TCP)', () => {
    const decoded = decoder.decode(minimalValidIPv4Buffer);

    it('should decode successfully', () => {
      expect(decoded).not.toBeNull();
    });

    if (!decoded) return; // Type guard

    it('should correctly parse IPv4 header fields', () => {
      const data = decoded.data as IPv4Layer;
      expect(data.version).toBe(4);
      expect(data.ihl).toBe(5);
      expect(data.dscp).toBe(0);
      expect(data.ecn).toBe(0);
      expect(data.totalLength).toBe(20);
      expect(data.identification).toBe(0x1234);
      expect(data.flags).toBe(0);
      expect(data.fragmentOffset).toBe(0);
      expect(data.ttl).toBe(64);
      expect(data.protocol).toBe(6); // TCP
      expect(data.headerChecksum).toBe(0xabcd);
      expect(data.sourceIp).toBe('192.168.0.1');
      expect(data.destinationIp).toBe('10.0.0.1');
      expect(data.options).toBeUndefined();
    });

    it('should report correct headerLength and payload', () => {
      expect(decoded.headerLength).toBe(20); // IHL * 4
      expect(decoded.payload.length).toBe(0); // Total Length - Header Length
    });

    it('should report correct next protocol type', () => {
      expect(decoder.nextProtocolType(decoded.data as IPv4Layer)).toBe(6); // TCP
    });
  });

  describe('IPv4 Packet with Options (UDP)', () => {
    const decoded = decoder.decode(ipv4WithOptionsMenuBuffer);

    it('should decode successfully', () => {
      expect(decoded).not.toBeNull();
    });

    if (!decoded) return; // Type guard

    it('should correctly parse IPv4 header fields with options', () => {
      const data = decoded.data as IPv4Layer;
      expect(data.version).toBe(4);
      expect(data.ihl).toBe(6); // 6 * 4 = 24 bytes
      expect(data.dscp).toBe(0);
      expect(data.ecn).toBe(0);
      expect(data.totalLength).toBe(24);
      expect(data.identification).toBe(0x5678);
      expect(data.flags).toBe(0b010); // Don't Fragment bit
      expect(data.fragmentOffset).toBe(0);
      expect(data.ttl).toBe(128);
      expect(data.protocol).toBe(17); // UDP
      expect(data.headerChecksum).toBe(0xdcba);
      expect(data.sourceIp).toBe('172.16.0.1');
      expect(data.destinationIp).toBe('172.16.0.2');
      expect(data.options).toBeDefined();
      expect(data.options?.length).toBe(4); // IHL (6*4) - MinHeader (5*4) = 24 - 20 = 4
      expect(data.options).toEqual(Buffer.from([0x01, 0x01, 0x01, 0x01]));
    });

    it('should report correct headerLength and payload', () => {
      expect(decoded.headerLength).toBe(24); // IHL * 4
      expect(decoded.payload.length).toBe(0); // Total Length - Header Length
    });

    it('should report correct next protocol type', () => {
      expect(decoder.nextProtocolType(decoded.data as IPv4Layer)).toBe(17); // UDP
    });
  });

  describe('IPv4 Packet with Payload (ICMP)', () => {
    const decoded = decoder.decode(ipv4IcmpBuffer);

    it('should decode successfully', () => {
      expect(decoded).not.toBeNull();
    });

    if (!decoded) return; // Type guard

    it('should correctly parse IPv4 header fields', () => {
      const data = decoded.data as IPv4Layer;
      expect(data.version).toBe(4);
      expect(data.ihl).toBe(5);
      expect(data.totalLength).toBe(28); // 20 header + 8 payload
      expect(data.protocol).toBe(1); // ICMP
      expect(data.sourceIp).toBe('10.1.1.10');
      expect(data.destinationIp).toBe('10.1.1.20');
      expect(data.options).toBeUndefined();
    });

    it('should report correct headerLength and payload', () => {
      expect(decoded.headerLength).toBe(20);
      expect(decoded.payload.length).toBe(8); // Total Length (28) - Header Length (20)
      expect(decoded.payload).toEqual(
        Buffer.from([0x08, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]),
      );
    });

    it('should report correct next protocol type', () => {
      expect(decoder.nextProtocolType(decoded.data as IPv4Layer)).toBe(1); // ICMP
    });
  });

describe('Detailed Field Validation', () => {
    it('should correctly parse various DSCP and ECN values', () => {
      const testCases = [
        { dscp: 0, ecn: 0, byteValue: 0x00 }, // Standard
        { dscp: 0b101110, ecn: 0b00, byteValue: 0xb8 }, // DSCP EF (46), ECN Not-ECT
        { dscp: 0b001010, ecn: 0b01, byteValue: 0x29 }, // DSCP AF11 (10), ECN ECT(1)
        { dscp: 0b001110, ecn: 0b10, byteValue: 0x3a }, // DSCP AF13 (14), ECN ECT(0)
        { dscp: 0b010000, ecn: 0b11, byteValue: 0x43 }, // DSCP CS2 (16), ECN CE
        { dscp: 0b111111, ecn: 0b11, byteValue: 0xff }, // Max DSCP, Max ECN
      ];

      testCases.forEach(tc => {
        const buffer = Buffer.from(minimalValidIPv4Buffer);
        buffer[1] = tc.byteValue; // Modify the DSCP/ECN byte

        const decoded = decoder.decode(buffer);
        expect(decoded.data.dscp).toBe(tc.dscp);
        expect(decoded.data.ecn).toBe(tc.ecn);
      });
    });

    it('should correctly parse various TTL values', () => {
      const testCases = [1, 32, 64, 128, 255];
      testCases.forEach(ttl => {
        const buffer = Buffer.from(minimalValidIPv4Buffer);
        buffer[8] = ttl; // Modify TTL byte
        const decoded = decoder.decode(buffer);
        expect(decoded.data.ttl).toBe(ttl);
      });
    });

    it('should correctly parse various Flags values', () => {
      // Flags are the top 3 bits of the 16-bit word at offset 6
      // 0x8000 -> Reserved (must be 0) - not testing this as it's invalid
      // 0x4000 -> Don't Fragment (DF)
      // 0x2000 -> More Fragments (MF)
      const testCases = [
        { flags: 0b000, fragmentOffset: 0, wordValue: 0x0000 }, // No flags, no offset
        { flags: 0b010, fragmentOffset: 0, wordValue: 0x4000 }, // DF set
        { flags: 0b001, fragmentOffset: 0, wordValue: 0x2000 }, // MF set
        { flags: 0b001, fragmentOffset: 100, wordValue: 0x2000 | 100 }, // MF set with offset
        { flags: 0b000, fragmentOffset: 8191, wordValue: 0x1FFF }, // Max offset (13 bits)
        { flags: 0b010, fragmentOffset: 1234, wordValue: 0x4000 | 1234 }, // DF with offset (offset should be 0 if DF is set, but parser should still parse)
      ];

      testCases.forEach(tc => {
        const buffer = Buffer.from(minimalValidIPv4Buffer);
        buffer.writeUInt16BE(tc.wordValue, 6); // Modify Flags/Fragment Offset word
        const decoded = decoder.decode(buffer);
        expect(decoded.data.flags).toBe(tc.flags);
        expect(decoded.data.fragmentOffset).toBe(tc.fragmentOffset);
      });
    });
it('should correctly extract IPv4 options of various lengths', () => {
      const baseHeader = [
        // 0x40, // Version 4, IHL will be modified
        0x00, // DSCP 0, ECN 0
        0x00, 0x00, // Total Length (will be modified)
        0x12, 0x34, // Identification
        0x00, 0x00, // Flags 0, Fragment Offset 0
        0x40, // TTL 64
        0x06, // Protocol TCP (6)
        0xab, 0xcd, // Header Checksum (dummy)
        192, 168, 0, 1, // Source IP
        10, 0, 0, 1, // Destination IP
      ];

      const testCases = [
        { ihl: 6, options: [0x01, 0x01, 0x01, 0x01], description: '4 bytes of NOPs' }, // 24 byte header
        { ihl: 7, options: [0x94, 0x04, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01], description: 'Router Alert (RFC 2113) + 4 NOPs for padding' }, // 28 byte header
        { ihl: 15, options: Array(40).fill(0x01), description: 'Max options length (40 bytes of NOPs)'} // 60 byte header
      ];

      testCases.forEach(tc => {
        const optionsBuffer = Buffer.from(tc.options);
        const headerLength = tc.ihl * 4;
        const totalLength = headerLength; // Assuming no payload for these option tests

        const buffer = Buffer.alloc(totalLength);
        buffer[0] = (0x4 << 4) | tc.ihl; // Set Version and IHL
        Buffer.from(baseHeader).copy(buffer, 1, 0, 19); // Copy the rest of the base header (excluding first byte)
        buffer.writeUInt16BE(totalLength, 2); // Set Total Length
        optionsBuffer.copy(buffer, 20); // Copy options

        const decoded = decoder.decode(buffer);
        expect(decoded.data.ihl).toBe(tc.ihl);
        expect(decoded.headerLength).toBe(headerLength);
        expect(decoded.data.options).toBeDefined();
        expect(decoded.data.options).toEqual(optionsBuffer);
        expect(decoded.payload.length).toBe(0);
      });
    });

    it('should return undefined for options if IHL is 5', () => {
      const decoded = decoder.decode(minimalValidIPv4Buffer); // IHL is 5
      expect(decoded.data.ihl).toBe(5);
      expect(decoded.data.options).toBeUndefined();
    });
  });
  describe('Error Handling', () => {
    it('should throw BufferOutOfBoundsError for buffer smaller than minimal header size', () => {
      const tooSmallBuffer = Buffer.from([0x45, 0x00, 0x00, 0x13]); // Only 4 bytes
      expect(() => decoder.decode(tooSmallBuffer)).toThrow(BufferOutOfBoundsError);
      expect(() => decoder.decode(tooSmallBuffer)).toThrow(
        'Buffer too small for a minimal IPv4 header at offset 0. Expected 20 bytes, got 4.',
      );
    });

    it('should throw BufferOutOfBoundsError if IHL indicates header larger than buffer', () => {
      // IHL 6 (24 bytes), but buffer is only 20 bytes. TotalLength also 24.
      const ihlTooLargeBuffer = Buffer.from([
        0x46, // Version 4, IHL 6 (24 bytes)
        0x00, // DSCP 0, ECN 0
        0x00,
        0x18, // Total Length 24
        0x12,
        0x34, // Identification
        0x00,
        0x00, // Flags 0, Fragment Offset 0
        0x40, // TTL 64
        0x06, // Protocol TCP (6)
        0xab,
        0xcd, // Header Checksum (dummy)
        192,
        168,
        0,
        1, // Source IP: 192.168.0.1
        10,
        0,
        0,
        1, // Destination IP: 10.0.0.1
        // Missing 4 bytes for options
      ]);
      expect(() => decoder.decode(ihlTooLargeBuffer)).toThrow(BufferOutOfBoundsError);
      expect(() => decoder.decode(ihlTooLargeBuffer)).toThrow(
        'Buffer too small for indicated IPv4 header length (24 bytes) at offset 0. Buffer remaining: 20 bytes.',
      );
    });

    it('should handle (log warning for) TotalLength exceeding buffer size but still return truncated payload', () => {
      // Header is 20 bytes. TotalLength says 30 bytes. Buffer provides header + 5 bytes payload (total 25 bytes).
      const totalLengthExceedsBuffer = Buffer.from([
        0x45, // Version 4, IHL 5
        0x00, // DSCP 0, ECN 0
        0x00,
        0x1e, // Total Length 30 (but buffer will be shorter)
        0x12,
        0x34, // Identification
        0x00,
        0x00, // Flags 0, Fragment Offset 0
        0x40, // TTL 64
        0x06, // Protocol TCP (6)
        0xab,
        0xcd, // Header Checksum (dummy)
        192,
        168,
        0,
        1,
        10,
        0,
        0,
        1,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05, // Only 5 bytes of payload
      ]);
      // Spy on console.warn or your logger
      const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

      const decoded = decoder.decode(totalLengthExceedsBuffer);
      expect(decoded).not.toBeNull();
      if (!decoded) return;

      expect(decoded.data.totalLength).toBe(30);
      expect(decoded.headerLength).toBe(20);
      // Payload should be what's available: 25 (buffer total) - 20 (header) = 5
      expect(decoded.payload.length).toBe(5);
      expect(decoded.payload).toEqual(Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05]));

      // Check if the warning was logged (assuming your logger uses console.warn for LogLevel.WARN)
      // This depends on how logWarning is implemented in ipv4-decoder.ts
      // For now, we'll assume it logs. The actual check might need adjustment.
      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          'IPv4: totalLength (30) implies payload of 10 bytes, but only 5 bytes available in buffer after header. Payload will be truncated.',
        ),
      );
      consoleWarnSpy.mockRestore();
    });

    it('should throw PcapDecodingError for invalid IPv4 version', () => {
      const invalidVersionBuffer = Buffer.from([
        0x55, // Version 5, IHL 5
        0x00,
        0x00,
        0x14,
        0x12,
        0x34,
        0x00,
        0x00,
        0x40,
        0x06,
        0xab,
        0xcd,
        192,
        168,
        0,
        1,
        10,
        0,
        0,
        1,
      ]);
      expect(() => decoder.decode(invalidVersionBuffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(invalidVersionBuffer)).toThrow(
        'Invalid IPv4 version at offset 0: 5. Expected 4.',
      );
    });

    // The test below for negative payload length already expects PcapDecodingError and the correct message.
    it('should throw PcapDecodingError if calculated payload length is negative (IHL > TotalLength/4)', () => {
      // IHL = 6 (24 bytes header), TotalLength = 20 bytes. This is an invalid packet.
      const headerLongerThanTotalBuffer = Buffer.from([
        0x46, // Version 4, IHL 6 (24 bytes)
        0x00, // DSCP 0, ECN 0
        0x00,
        0x14, // Total Length 20
        0x12,
        0x34, // Identification
        0x00,
        0x00, // Flags 0, Fragment Offset 0
        0x40, // TTL 64
        0x06, // Protocol TCP (6)
        0xab,
        0xcd, // Header Checksum (dummy)
        192,
        168,
        0,
        1,
        10,
        0,
        0,
        1,
        0x01,
        0x02,
        0x03,
        0x04, // Options to make header 24 bytes
      ]);
      expect(() => decoder.decode(headerLongerThanTotalBuffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(headerLongerThanTotalBuffer)).toThrow(
        'Calculated payload length is negative (-4) at offset 0. totalLength: 20, headerLength: 24',
      );
    });

it('should throw PcapDecodingError for IHL < 5 (e.g., 4) even if buffer is large enough for minimal header', () => {
      // Buffer is 20 bytes (MIN_IPV4_HEADER_SIZE), IHL is 4 (implies 16-byte header)
      // Version 4, IHL 4
      // Total Length: 20 (to match buffer size and avoid other errors like negative payload)
      // Other fields are minimal/dummy to ensure the IHL check is the one failing.
      const ihlTooSmallBuffer = Buffer.from([
        0x44, // Version 4, IHL 4
        0x00, // DSCP 0, ECN 0
        0x00,
        0x14, // Total Length 20
        0x12,
        0x34, // Identification
        0x00,
        0x00, // Flags 0, Fragment Offset 0
        0x40, // TTL 64
        0x06, // Protocol TCP (6)
        0xab,
        0xcd, // Header Checksum (dummy)
        192,
        168,
        0,
        1, // Source IP
        10,
        0,
        0,
        1, // Destination IP
      ]);

      expect(() => decoder.decode(ihlTooSmallBuffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(ihlTooSmallBuffer)).toThrow(
        'Invalid IPv4 IHL at offset 0: 4. Minimum value is 5 (for a 20-byte header).',
      );
    });

  });
});
