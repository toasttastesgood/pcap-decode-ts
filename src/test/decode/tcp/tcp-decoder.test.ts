import { describe, it, expect, beforeEach } from 'vitest';
import { TCPDecoder } from '../../../decode/tcp/tcp-decoder';
import { TCPLayer } from '../../../decode/tcp/tcp-layer';
import { BufferOutOfBoundsError, PcapDecodingError } from '../../../errors';
import { DecoderOutputLayer } from '../../../decode/decoder';

describe('TCPDecoder', () => {
  let decoder: TCPDecoder;

  beforeEach(() => {
    decoder = new TCPDecoder();
  });

  it('should have the correct protocolName', () => {
    expect(decoder.protocolName).toBe('TCP');
  });

  it('should return null for nextProtocolType', () => {
    const mockTcpLayer: TCPLayer = {
      sourcePort: 12345,
      destinationPort: 80,
      sequenceNumber: 1000,
      acknowledgmentNumber: 2000,
      dataOffset: 5,
      reserved: 0,
      flags: {
        ns: false,
        cwr: false,
        ece: false,
        urg: false,
        ack: true,
        psh: false,
        rst: false,
        syn: false,
        fin: false,
      },
      windowSize: 65535,
      checksum: 0x1234,
      urgentPointer: 0,
    };
    expect(decoder.nextProtocolType(mockTcpLayer)).toBeNull();
  });

  describe('decode', () => {
    it('should throw BufferOutOfBoundsError if buffer is too small for minimal header', () => {
      const buffer = Buffer.alloc(19); // Less than 20 bytes
      expect(() => decoder.decode(buffer)).toThrow(BufferOutOfBoundsError);
      expect(() => decoder.decode(buffer)).toThrow(
        'Buffer too small for TCP header. Expected at least 20 bytes, got 19.',
      );
    });

    it('should decode a minimal TCP segment (SYN packet, no options)', () => {
      // TCP Header: 20 bytes
      // Source Port: 12345 (0x3039)
      // Destination Port: 80 (0x0050)
      // Sequence Number: 1000 (0x000003E8)
      // Acknowledgment Number: 0 (0x00000000)
      // Data Offset: 5 (0x5000 -> 0101 0000 0000 0000), Reserved: 0, Flags: SYN (0x0002) -> 0x5002
      // Window Size: 65535 (0xFFFF)
      // Checksum: 0xABCD (placeholder)
      // Urgent Pointer: 0 (0x0000)
      const buffer = Buffer.from([
        0x30,
        0x39, // Source Port
        0x00,
        0x50, // Destination Port
        0x00,
        0x00,
        0x03,
        0xe8, // Sequence Number
        0x00,
        0x00,
        0x00,
        0x00, // Acknowledgment Number
        0x50,
        0x02, // Data Offset (5), Reserved (0), Flags (SYN)
        0xff,
        0xff, // Window Size
        0xab,
        0xcd, // Checksum
        0x00,
        0x00, // Urgent Pointer
        // Payload data
        0xde,
        0xad,
        0xbe,
        0xef,
      ]);

      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;

      expect(result).toBeDefined();
      expect(result.protocolName).toBe('TCP');
      expect(result.headerLength).toBe(20);
      expect(result.data.sourcePort).toBe(12345);
      expect(result.data.destinationPort).toBe(80);
      expect(result.data.sequenceNumber).toBe(1000);
      expect(result.data.acknowledgmentNumber).toBe(0);
      expect(result.data.dataOffset).toBe(5);
      expect(result.data.reserved).toBe(0);
      expect(result.data.flags).toEqual({
        ns: false,
        cwr: false,
        ece: false,
        urg: false,
        ack: false,
        psh: false,
        rst: false,
        syn: true,
        fin: false,
      });
      expect(result.data.windowSize).toBe(65535);
      expect(result.data.checksum).toBe(0xabcd);
      expect(result.data.urgentPointer).toBe(0);
      expect(result.data.options).toBeUndefined();
      expect(result.payload).toEqual(Buffer.from([0xde, 0xad, 0xbe, 0xef]));
    });

    it('should decode a TCP segment with ACK and PSH flags', () => {
      // Data Offset: 5 (0x5000), Reserved: 0, Flags: ACK (0x0010) + PSH (0x0008) = 0x0018 -> 0x5018
      const buffer = Buffer.from([
        0xc0,
        0x01, // Source Port: 49153
        0x01,
        0xbb, // Destination Port: 443
        0x00,
        0x00,
        0x00,
        0x01, // Sequence Number: 1
        0x00,
        0x00,
        0x00,
        0x02, // Acknowledgment Number: 2
        0x50,
        0x18, // Data Offset (5), Reserved (0), Flags (ACK, PSH)
        0x7f,
        0xff, // Window Size: 32767
        0xdc,
        0xba, // Checksum
        0x00,
        0x00, // Urgent Pointer
        0x01,
        0x02,
        0x03,
        0x04, // Payload
      ]);

      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;

      expect(result.data.sourcePort).toBe(49153);
      expect(result.data.destinationPort).toBe(443);
      expect(result.data.sequenceNumber).toBe(1);
      expect(result.data.acknowledgmentNumber).toBe(2);
      expect(result.data.dataOffset).toBe(5);
      expect(result.data.flags).toEqual({
        ns: false,
        cwr: false,
        ece: false,
        urg: false,
        ack: true,
        psh: true,
        rst: false,
        syn: false,
        fin: false,
      });
      expect(result.data.windowSize).toBe(32767);
      expect(result.data.checksum).toBe(0xdcba);
      expect(result.data.urgentPointer).toBe(0);
      expect(result.data.options).toBeUndefined();
      expect(result.payload).toEqual(Buffer.from([0x01, 0x02, 0x03, 0x04]));
    });

    it('should decode a TCP segment with options (MSS)', () => {
      // Data Offset: 6 (0x6000 -> 0110 ....), Reserved: 0, Flags: SYN (0x0002) -> 0x6002
      // Options: MSS (Kind=2, Length=4, Value=1460=0x05B4) -> 02 04 05 B4
      // Header length = 6 * 4 = 24 bytes
      const buffer = Buffer.from([
        0x30,
        0x39, // Source Port
        0x00,
        0x50, // Destination Port
        0x00,
        0x00,
        0x03,
        0xe8, // Sequence Number
        0x00,
        0x00,
        0x00,
        0x00, // Acknowledgment Number
        0x60,
        0x02, // Data Offset (6), Reserved (0), Flags (SYN)
        0xff,
        0xff, // Window Size
        0xab,
        0xcd, // Checksum
        0x00,
        0x00, // Urgent Pointer
        // Options (4 bytes)
        0x02,
        0x04,
        0x05,
        0xb4, // MSS Option
        // Payload
        0xda,
        0xda,
      ]);

      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;

      expect(result.headerLength).toBe(24);
      expect(result.data.dataOffset).toBe(6);
      expect(result.data.options).toBeDefined();
      expect(result.data.options).toEqual(Buffer.from([0x02, 0x04, 0x05, 0xb4]));
      expect(result.payload).toEqual(Buffer.from([0xda, 0xda]));
    });

    it('should decode a TCP segment with NS flag', () => {
      // Data Offset: 5 (0x5000), Reserved: 0, Flags: NS (0x0100) + SYN (0x0002) = 0x0102 -> 0x5102
      const buffer = Buffer.from([
        0x30,
        0x39, // Source Port
        0x00,
        0x50, // Destination Port
        0x00,
        0x00,
        0x03,
        0xe8, // Sequence Number
        0x00,
        0x00,
        0x00,
        0x00, // Acknowledgment Number
        0x51,
        0x02, // Data Offset (5), Reserved (0), Flags (NS, SYN)
        0xff,
        0xff, // Window Size
        0xab,
        0xcd, // Checksum
        0x00,
        0x00, // Urgent Pointer
      ]);

      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;
      expect(result.data.flags.ns).toBe(true);
      expect(result.data.flags.syn).toBe(true);
      expect(result.data.reserved).toBe(0); // Reserved bits should not include NS
    });

    it('should throw BufferOutOfBoundsError if dataOffset indicates header larger than buffer', () => {
      // Data Offset: 8 (0x8000 -> 1000 ....), Header length = 8 * 4 = 32 bytes
      // Buffer is only 20 bytes long.
      const buffer = Buffer.from([
        0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x80, 0x02, 0xff,
        0xff, 0xab, 0xcd, 0x00, 0x00,
      ]);
      expect(() => decoder.decode(buffer)).toThrow(BufferOutOfBoundsError);
      expect(() => decoder.decode(buffer)).toThrow(
        'Buffer too small for declared TCP header length. Expected 32 bytes (data_offset*4), got 20.',
      );
    });

    it('should throw PcapDecodingError if dataOffset is less than 5', () => {
      // Data Offset: 4 (0x4000 -> 0100 ....), Header length = 4 * 4 = 16 bytes (invalid)
      const buffer = Buffer.from([
        0x30,
        0x39,
        0x00,
        0x50,
        0x00,
        0x00,
        0x03,
        0xe8,
        0x00,
        0x00,
        0x00,
        0x00,
        0x40,
        0x02, // Data Offset 4
        0xff,
        0xff,
        0xab,
        0xcd,
        0x00,
        0x00,
      ]);
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow(
        'Invalid TCP data offset 4 at offset 12. Resulting header length 16 is less than minimum 20.',
      );
    });

    it('should decode a TCP segment with SYN-ACK flags', () => {
      // Data Offset: 5 (0x5000), Flags: SYN (0x0002) + ACK (0x0010) = 0x0012 -> 0x5012
      const buffer = Buffer.from([
        0x00,
        0x50, // Source Port: 80
        0x30,
        0x39, // Destination Port: 12345
        0x00,
        0x00,
        0x00,
        0x00, // Sequence Number: 0
        0x00,
        0x00,
        0x03,
        0xe9, // Acknowledgment Number: 1001
        0x50,
        0x12, // Data Offset (5), Reserved (0), Flags (SYN, ACK)
        0x7a,
        0x00, // Window Size: 31232
        0x12,
        0x34, // Checksum
        0x00,
        0x00, // Urgent Pointer
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;
      expect(result.data.flags).toEqual({
        ns: false,
        cwr: false,
        ece: false,
        urg: false,
        ack: true,
        psh: false,
        rst: false,
        syn: true,
        fin: false,
      });
      expect(result.data.sourcePort).toBe(80);
      expect(result.data.destinationPort).toBe(12345);
      expect(result.data.sequenceNumber).toBe(0);
      expect(result.data.acknowledgmentNumber).toBe(1001);
    });

    it('should decode a TCP segment with FIN flag', () => {
      // Data Offset: 5 (0x5000), Flags: FIN (0x0001) -> 0x5001
      const buffer = Buffer.from([
        0x30,
        0x39,
        0x00,
        0x50,
        0x00,
        0x00,
        0x04,
        0x00, // Seq 1024
        0x00,
        0x00,
        0x00,
        0x0a, // Ack 10
        0x50,
        0x01, // Data Offset (5), Flags (FIN)
        0xff,
        0xff,
        0xab,
        0xcd,
        0x00,
        0x00,
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;
      expect(result.data.flags).toEqual({
        ns: false,
        cwr: false,
        ece: false,
        urg: false,
        ack: false,
        psh: false,
        rst: false,
        syn: false,
        fin: true,
      });
    });

    it('should decode a TCP segment with RST flag', () => {
      // Data Offset: 5 (0x5000), Flags: RST (0x0004) -> 0x5004
      const buffer = Buffer.from([
        0x30,
        0x39,
        0x00,
        0x50,
        0x00,
        0x00,
        0x04,
        0x00,
        0x00,
        0x00,
        0x00,
        0x0a,
        0x50,
        0x04, // Data Offset (5), Flags (RST)
        0xff,
        0xff,
        0xab,
        0xcd,
        0x00,
        0x00,
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;
      expect(result.data.flags).toEqual({
        ns: false,
        cwr: false,
        ece: false,
        urg: false,
        ack: false,
        psh: false,
        rst: true,
        syn: false,
        fin: false,
      });
    });

    it('should decode a TCP segment with URG flag and urgent pointer', () => {
      // Data Offset: 5 (0x5000), Flags: URG (0x0020) -> 0x5020
      const buffer = Buffer.from([
        0x30,
        0x39,
        0x00,
        0x50,
        0x00,
        0x00,
        0x04,
        0x00,
        0x00,
        0x00,
        0x00,
        0x0a,
        0x50,
        0x20, // Data Offset (5), Flags (URG)
        0xff,
        0xff,
        0xab,
        0xcd,
        0x00,
        0x0f, // Urgent Pointer 15
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;
      expect(result.data.flags).toEqual({
        ns: false,
        cwr: false,
        ece: false,
        urg: true,
        ack: false,
        psh: false,
        rst: false,
        syn: false,
        fin: false,
      });
      expect(result.data.urgentPointer).toBe(15);
    });

    it('should decode a TCP segment with CWR flag', () => {
      // Data Offset: 5 (0x5000), Flags: CWR (0x0080) -> 0x5080
      const buffer = Buffer.from([
        0x30,
        0x39,
        0x00,
        0x50,
        0x00,
        0x00,
        0x04,
        0x00,
        0x00,
        0x00,
        0x00,
        0x0a,
        0x50,
        0x80, // Data Offset (5), Flags (CWR)
        0xff,
        0xff,
        0xab,
        0xcd,
        0x00,
        0x00,
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;
      expect(result.data.flags.cwr).toBe(true);
    });

    it('should decode a TCP segment with ECE flag', () => {
      // Data Offset: 5 (0x5000), Flags: ECE (0x0040) -> 0x5040
      const buffer = Buffer.from([
        0x30,
        0x39,
        0x00,
        0x50,
        0x00,
        0x00,
        0x04,
        0x00,
        0x00,
        0x00,
        0x00,
        0x0a,
        0x50,
        0x40, // Data Offset (5), Flags (ECE)
        0xff,
        0xff,
        0xab,
        0xcd,
        0x00,
        0x00,
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;
      expect(result.data.flags.ece).toBe(true);
    });
it('should decode a TCP segment with all flags set', () => {
      // Data Offset: 5 (0x5000), Reserved: 0, All Flags: (0x01FF) -> 0x51FF
      const buffer = Buffer.from([
        0x12, 0x34, // Source Port
        0x56, 0x78, // Destination Port
        0x00, 0x00, 0x00, 0x01, // Sequence Number
        0x00, 0x00, 0x00, 0x02, // Acknowledgment Number
        0x51, 0xFF, // Data Offset (5), Reserved (0), All Flags
        0x7F, 0xFF, // Window Size
        0xAB, 0xCD, // Checksum
        0x00, 0x0F, // Urgent Pointer (relevant if URG is set)
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;
      expect(result.data.flags).toEqual({
        ns: true, cwr: true, ece: true, urg: true,
        ack: true, psh: true, rst: true, syn: true, fin: true,
      });
      expect(result.data.dataOffset).toBe(5);
      expect(result.data.reserved).toBe(0);
      expect(result.data.urgentPointer).toBe(0x0F);
      expect(result.headerLength).toBe(20);
      expect(result.payload.length).toBe(0);
    });

    it('should decode a TCP segment with no payload', () => {
      const buffer = Buffer.from([
        0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x03, 0xE8,
        0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xFF, 0xFF,
        0xAB, 0xCD, 0x00, 0x00,
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;
      expect(result.headerLength).toBe(20);
      expect(result.data.dataOffset).toBe(5);
      expect(result.payload).toBeDefined();
      expect(result.payload.length).toBe(0);
      expect(result.data.options).toBeUndefined();
    });

    it('should decode urgentPointer even if URG flag is not set', () => {
      const buffer = Buffer.from([
        0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x03, 0xE8,
        0x00, 0x00, 0x00, 0x00, 0x50, 0x02, // Flags (SYN only)
        0xFF, 0xFF, 0xAB, 0xCD, 0x00, 0x0F, // Urgent Pointer 15
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;
      expect(result.data.flags.urg).toBe(false);
      expect(result.data.urgentPointer).toBe(15);
    });

    it('should decode TCP options: Window Scale with NOP padding', () => {
      const buffer = Buffer.from([
        0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x03, 0xE8,
        0x00, 0x00, 0x00, 0x00, 0x60, 0x02, // Data Offset (6)
        0xFF, 0xFF, 0xAB, 0xCD, 0x00, 0x00,
        0x03, 0x03, 0x07, 0x01, // Window Scale (7), NOP
        0xDE, 0xAD,
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;
      expect(result.headerLength).toBe(24);
      expect(result.data.options).toEqual(Buffer.from([0x03, 0x03, 0x07, 0x01]));
      expect(result.payload).toEqual(Buffer.from([0xDE, 0xAD]));
    });

    it('should decode TCP options: SACK Permitted with NOP padding', () => {
      const buffer = Buffer.from([
        0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x03, 0xE8,
        0x00, 0x00, 0x00, 0x00, 0x60, 0x02, // Data Offset (6)
        0xFF, 0xFF, 0xAB, 0xCD, 0x00, 0x00,
        0x04, 0x02, 0x01, 0x01, // SACK Permitted, NOP, NOP
        0xDE, 0xAD,
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;
      expect(result.headerLength).toBe(24);
      expect(result.data.options).toEqual(Buffer.from([0x04, 0x02, 0x01, 0x01]));
      expect(result.payload).toEqual(Buffer.from([0xDE, 0xAD]));
    });

    it('should decode TCP options: Timestamps with NOP padding', () => {
      const buffer = Buffer.from([
        0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x03, 0xE8,
        0x00, 0x00, 0x00, 0x00, 0x80, 0x02, // Data Offset (8)
        0xFF, 0xFF, 0xAB, 0xCD, 0x00, 0x00,
        0x08, 0x0A, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x01, // Timestamps, NOP, NOP
        0xDE, 0xAD,
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;
      expect(result.headerLength).toBe(32);
      expect(result.data.options).toEqual(
        Buffer.from([0x08, 0x0A, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x01]),
      );
      expect(result.payload).toEqual(Buffer.from([0xDE, 0xAD]));
    });

    it('should decode TCP with multiple options (MSS, SACK Permitted, Window Scale, Timestamps) and padding', () => {
      const optionsBuffer = Buffer.from([
        0x02, 0x04, 0x05, 0xB4, // MSS
        0x04, 0x02,             // SACK Permitted
        0x03, 0x03, 0x0A,       // Window Scale
        0x08, 0x0A, 0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x02, // Timestamps
        0x01,                   // NOP padding
      ]); // Total 20 bytes options
      const headerNoOptions = Buffer.from([
        0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x03, 0xE8,
        0x00, 0x00, 0x00, 0x00, 0xA0, 0x02, // Data Offset (10)
        0xFF, 0xFF, 0xAB, 0xCD, 0x00, 0x00,
      ]);
      const payloadBuffer = Buffer.from([0xDE, 0xAD]);
      const buffer = Buffer.concat([headerNoOptions, optionsBuffer, payloadBuffer]);

      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;
      expect(result.headerLength).toBe(40);
      expect(result.data.options).toEqual(optionsBuffer);
      expect(result.payload).toEqual(payloadBuffer);
    });

    it('should decode TCP options: EOL and padding', () => {
      const optionsData = Buffer.from([0x02, 0x04, 0x05, 0xB4, 0x00, 0x01, 0x01, 0x01]); // MSS, EOL, NOP, NOP, NOP
      const buffer = Buffer.from([
        0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x03, 0xE8,
        0x00, 0x00, 0x00, 0x00, 0x70, 0x02, // Data Offset (7)
        0xFF, 0xFF, 0xAB, 0xCD, 0x00, 0x00,
        ...optionsData,
        0xDE, 0xAD,
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;
      expect(result.headerLength).toBe(28);
      expect(result.data.options).toEqual(optionsData);
      expect(result.payload).toEqual(Buffer.from([0xDE, 0xAD]));
    });

    it('should decode TCP with maximum data offset (options fill 40 bytes)', () => {
      const fortyNops = Buffer.alloc(40, 0x01);
      const buffer = Buffer.from([
        0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x03, 0xE8,
        0x00, 0x00, 0x00, 0x00, 0xF0, 0x02, // Data Offset (15)
        0xFF, 0xFF, 0xAB, 0xCD, 0x00, 0x00,
        ...fortyNops,
        0xDE, 0xAD,
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;
      expect(result.headerLength).toBe(60);
      expect(result.data.options).toEqual(fortyNops);
      expect(result.payload).toEqual(Buffer.from([0xDE, 0xAD]));
    });

    it('should decode a TCP segment with non-zero reserved bits', () => {
      const buffer = Buffer.from([
        0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x02, 0x5E, 0x02, // Data Offset (5), Reserved (7), Flags (SYN)
        0x7F, 0xFF, 0xAB, 0xCD, 0x00, 0x00,
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<TCPLayer>;
      expect(result.data.dataOffset).toBe(5);
      expect(result.data.reserved).toBe(7);
      expect(result.data.flags.syn).toBe(true);
      expect(result.headerLength).toBe(20);
      expect(result.payload.length).toBe(0);
    });

    // TODO: Add tests for checksum validation (will require IP pseudo-header context)
  });
});
