import { describe, it, expect, beforeEach } from 'vitest';
import { ICMPv6Decoder, ICMPv6Layer } from '../../../decode/icmpv6/icmpv6-decoder';
import { BufferOutOfBoundsError } from '../../../errors';
import { DecoderOutputLayer } from '../../../decode/decoder';

describe('ICMPv6Decoder', () => {
  let decoder: ICMPv6Decoder;

  beforeEach(() => {
    decoder = new ICMPv6Decoder();
  });

  it('should have the correct protocolName', () => {
    expect(decoder.protocolName).toBe('ICMPv6');
  });

  it('should return null for nextProtocolType', () => {
    const mockLayerData: ICMPv6Layer = {
      type: 128, // Echo Request
      code: 0,
      checksum: 0x1234,
      data: Buffer.from([0x00, 0x01, 0x00, 0x0a]), // Identifier, Sequence Number
    };
    expect(decoder.nextProtocolType(mockLayerData)).toBeNull();
  });

  describe('decode', () => {
    it('should throw BufferOutOfBoundsError if buffer is too small for header', () => {
      const tooSmallBuffer = Buffer.from([0x80, 0x00, 0x12]); // 3 bytes, expecting 4
      expect(() => decoder.decode(tooSmallBuffer)).toThrow(BufferOutOfBoundsError);
      expect(() => decoder.decode(tooSmallBuffer)).toThrow(
        'Buffer too small for ICMPv6 header. Expected at least 4 bytes, got 3.',
      );
    });

    it('should correctly decode an Echo Request packet', () => {
      // Type: 128 (Echo Request), Code: 0, Checksum: 0x7c40 (example)
      // Identifier: 0x0001, Sequence Number: 0x000a
      // Payload: "Hello" (0x48, 0x65, 0x6c, 0x6c, 0x6f)
      const echoRequestBuffer = Buffer.from([
        0x80,
        0x00,
        0x7c,
        0x40, // Type, Code, Checksum
        0x00,
        0x01,
        0x00,
        0x0a, // Identifier, Sequence Number
        0x48,
        0x65,
        0x6c,
        0x6c,
        0x6f, // "Hello"
      ]);

      const decoded = decoder.decode(echoRequestBuffer) as DecoderOutputLayer<ICMPv6Layer>;

      expect(decoded).not.toBeNull();
      expect(decoded.protocolName).toBe('ICMPv6');
      expect(decoded.headerLength).toBe(4);
      expect(decoded.data.type).toBe(128);
      expect(decoded.data.code).toBe(0);
      expect(decoded.data.checksum).toBe(0x7c40);
      expect(decoded.data.data).toEqual(
        Buffer.from([0x00, 0x01, 0x00, 0x0a, 0x48, 0x65, 0x6c, 0x6c, 0x6f]),
      );
      expect(decoded.payload).toEqual(Buffer.alloc(0));
    });

    it('should correctly decode an Echo Reply packet', () => {
      // Type: 129 (Echo Reply), Code: 0, Checksum: 0x7b40 (example)
      // Identifier: 0x0001, Sequence Number: 0x000a
      // Payload: "Hello" (0x48, 0x65, 0x6c, 0x6c, 0x6f)
      const echoReplyBuffer = Buffer.from([
        0x81,
        0x00,
        0x7b,
        0x40, // Type, Code, Checksum
        0x00,
        0x01,
        0x00,
        0x0a, // Identifier, Sequence Number
        0x48,
        0x65,
        0x6c,
        0x6c,
        0x6f, // "Hello"
      ]);

      const decoded = decoder.decode(echoReplyBuffer) as DecoderOutputLayer<ICMPv6Layer>;

      expect(decoded).not.toBeNull();
      expect(decoded.protocolName).toBe('ICMPv6');
      expect(decoded.headerLength).toBe(4);
      expect(decoded.data.type).toBe(129);
      expect(decoded.data.code).toBe(0);
      expect(decoded.data.checksum).toBe(0x7b40);
      expect(decoded.data.data).toEqual(
        Buffer.from([0x00, 0x01, 0x00, 0x0a, 0x48, 0x65, 0x6c, 0x6c, 0x6f]),
      );
      expect(decoded.payload).toEqual(Buffer.alloc(0));
    });

    it('should correctly decode a Neighbor Solicitation packet', () => {
      // Type: 135 (Neighbor Solicitation), Code: 0, Checksum: 0xabcd (example)
      // Reserved: 0x00000000
      // Target Address: fe80::1:2:3:4
      // Options (e.g. Source Link-Layer Address: 01:02:03:04:05:06)
      // For simplicity, only including Reserved and Target Address in this basic test
      const neighborSolicitationBuffer = Buffer.from([
        0x87,
        0x00,
        0xab,
        0xcd, // Type, Code, Checksum
        0x00,
        0x00,
        0x00,
        0x00, // Reserved
        0xfe,
        0x80,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // Target Address (fe80::1:2:3:4)
        0x00,
        0x01,
        0x00,
        0x02,
        0x00,
        0x03,
        0x00,
        0x04,
      ]);

      const decoded = decoder.decode(neighborSolicitationBuffer) as DecoderOutputLayer<ICMPv6Layer>;

      expect(decoded).not.toBeNull();
      expect(decoded.protocolName).toBe('ICMPv6');
      expect(decoded.headerLength).toBe(4);
      expect(decoded.data.type).toBe(135);
      expect(decoded.data.code).toBe(0);
      expect(decoded.data.checksum).toBe(0xabcd);
      expect(decoded.data.data).toEqual(
        Buffer.from([
          0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
          0x02, 0x00, 0x03, 0x00, 0x04,
        ]),
      );
      expect(decoded.payload).toEqual(Buffer.alloc(0));
    });

    it('should correctly decode a Neighbor Advertisement packet', () => {
      // Type: 136 (Neighbor Advertisement), Code: 0, Checksum: 0xefab (example)
      // Flags: 0x60 (Solicited + Override), Reserved: 0x000000
      // Target Address: fe80::5:6:7:8
      // Options (e.g. Target Link-Layer Address: 0a:0b:0c:0d:0e:0f)
      // For simplicity, only including Flags, Reserved and Target Address
      const neighborAdvertisementBuffer = Buffer.from([
        0x88,
        0x00,
        0xef,
        0xab, // Type, Code, Checksum
        0x60,
        0x00,
        0x00,
        0x00, // Flags (1 byte), Reserved (3 bytes)
        0xfe,
        0x80,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // Target Address (fe80::5:6:7:8)
        0x00,
        0x05,
        0x00,
        0x06,
        0x00,
        0x07,
        0x00,
        0x08,
      ]);

      const decoded = decoder.decode(
        neighborAdvertisementBuffer,
      ) as DecoderOutputLayer<ICMPv6Layer>;

      expect(decoded).not.toBeNull();
      expect(decoded.protocolName).toBe('ICMPv6');
      expect(decoded.headerLength).toBe(4);
      expect(decoded.data.type).toBe(136);
      expect(decoded.data.code).toBe(0);
      expect(decoded.data.checksum).toBe(0xefab);
      expect(decoded.data.data).toEqual(
        Buffer.from([
          0x60, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
          0x06, 0x00, 0x07, 0x00, 0x08,
        ]),
      );
      expect(decoded.payload).toEqual(Buffer.alloc(0));
    });

    // TODO: Add tests for checksum validation (once implemented)
    // TODO: Add tests for various data payloads and edge cases, including options for NS/NA
  });
});
