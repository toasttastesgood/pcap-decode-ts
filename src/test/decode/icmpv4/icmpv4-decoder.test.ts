import { describe, it, expect, beforeEach } from 'vitest';
import { Buffer } from 'buffer';
import { ICMPv4Decoder } from '../../../decode/icmpv4/icmpv4-decoder';
import {
  ICMPv4Layer,
  ICMPv4EchoData,
  ICMPv4DestinationUnreachableData,
  ICMPv4TimeExceededData,
  ICMPv4RedirectData,
  ICMPv4TimestampData,
  ICMPv4AddressMaskData,
  ICMPv4ParameterProblemData,
  ICMPv4RouterAdvertisementData,
  ICMPv4RouterSolicitationData,
} from '../../../decode/icmpv4/icmpv4-layer';
import { BufferOutOfBoundsError, PcapDecodingError } from '../../../errors';
import { DecoderOutputLayer } from '../../../decode/decoder';

// Helper to calculate checksum for test data generation
function calculateICMPv4ChecksumForTest(buffer: Buffer): number {
  let sum = 0;
  const tempBuffer = Buffer.from(buffer);
  // Zero out the checksum field for calculation if it's already set
  tempBuffer.writeUInt16BE(0, 2);

  for (let i = 0; i < tempBuffer.length; i += 2) {
    if (i + 1 < tempBuffer.length) {
      sum += tempBuffer.readUInt16BE(i);
    } else {
      sum += tempBuffer.readUInt8(i) << 8; // Pad with zero if odd length
    }
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return ~sum & 0xffff;
}

describe('ICMPv4Decoder', () => {
  let decoder: ICMPv4Decoder;

  beforeEach(() => {
    decoder = new ICMPv4Decoder();
  });

  it('should have the correct protocolName', () => {
    expect(decoder.protocolName).toBe('ICMPv4');
  });

  describe('Echo Request/Reply', () => {
    it('should correctly decode an Echo Request', () => {
      const buffer = Buffer.from([
        0x08, 0x00, 0x00, 0x00, // Type 8 (Echo), Code 0, Checksum placeholder
        0x12, 0x34, 0x56, 0x78, // Identifier, Sequence Number
        0x61, 0x62, 0x63, 0x64, // Data ("abcd")
      ]);
      const checksum = calculateICMPv4ChecksumForTest(buffer);
      buffer.writeUInt16BE(checksum, 2);

      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv4Layer>;
      expect(result.data.type).toBe(8);
      expect(result.data.code).toBe(0);
      expect(result.data.checksum).toBe(checksum);
      expect(result.data.validChecksum).toBe(true);
      expect(result.data.message).toBe('Echo Request');
      const echoData = result.data.data as ICMPv4EchoData;
      expect(echoData.identifier).toBe(0x1234);
      expect(echoData.sequenceNumber).toBe(0x5678);
      expect(echoData.echoData.toString('ascii')).toBe('abcd');
      expect(result.headerLength).toBe(buffer.length);
      expect(result.payload.length).toBe(0);
    });

    it('should correctly decode an Echo Reply', () => {
      const buffer = Buffer.from([
        0x00, 0x00, 0x00, 0x00, // Type 0 (Echo Reply), Code 0, Checksum placeholder
        0xab, 0xcd, 0xef, 0x01, // Identifier, Sequence Number
        0x68, 0x65, 0x6c, 0x6c, 0x6f, // Data ("hello")
      ]);
      const checksum = calculateICMPv4ChecksumForTest(buffer);
      buffer.writeUInt16BE(checksum, 2);

      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv4Layer>;
      expect(result.data.type).toBe(0);
      expect(result.data.code).toBe(0);
      expect(result.data.validChecksum).toBe(true);
      expect(result.data.message).toBe('Echo Reply');
      const echoData = result.data.data as ICMPv4EchoData;
      expect(echoData.identifier).toBe(0xabcd);
      expect(echoData.sequenceNumber).toBe(0xef01);
      expect(echoData.echoData.toString('ascii')).toBe('hello');
    });

    it('should throw BufferOutOfBoundsError for too short Echo Request', () => {
      const rawBuffer = Buffer.from([0x08, 0x00, 0x00, 0x00, 0x12, 0x34]); // Missing seq + data
      const checksum = calculateICMPv4ChecksumForTest(rawBuffer);
      rawBuffer.writeUInt16BE(checksum,2);
      expect(() => decoder.decode(rawBuffer)).toThrow(BufferOutOfBoundsError);
    });
  });

  describe('Destination Unreachable', () => {
    // Mock IP header + 8 bytes of original data
    const originalPacketPart = Buffer.from([
      // IP Header (20 bytes)
      0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x01, 0xac, 0x10, 0x0a, 0x02,
      // Original Data (8 bytes)
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ]);

    it('should decode Destination Unreachable (Host Unreachable)', () => {
      const icmpPart = Buffer.from([0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Type 3, Code 1, Checksum placeholder, Unused
      const buffer = Buffer.concat([icmpPart, originalPacketPart]);
      const checksum = calculateICMPv4ChecksumForTest(buffer);
      buffer.writeUInt16BE(checksum, 2);

      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv4Layer>;
      expect(result.data.type).toBe(3);
      expect(result.data.code).toBe(1);
      expect(result.data.validChecksum).toBe(true);
      expect(result.data.message).toBe('Destination Unreachable: Host Unreachable');
      const duData = result.data.data as ICMPv4DestinationUnreachableData;
      expect(duData.unused?.length).toBe(4);
      expect(duData.originalIpHeader.length).toBe(20);
      expect(duData.originalData.length).toBe(8);
      expect(duData.originalIpHeader[0]).toBe(0x45); // Check first byte of IP header
      expect(duData.originalData[0]).toBe(0x01); // Check first byte of original data
    });

    it('should decode Destination Unreachable (Fragmentation Needed)', () => {
      const icmpPart = Buffer.from([0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc]); // Type 3, Code 4, Checksum placeholder, 0, Next-Hop MTU (1500)
      const buffer = Buffer.concat([icmpPart, originalPacketPart]);
      const checksum = calculateICMPv4ChecksumForTest(buffer);
      buffer.writeUInt16BE(checksum, 2);

      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv4Layer>;
      expect(result.data.type).toBe(3);
      expect(result.data.code).toBe(4);
      expect(result.data.validChecksum).toBe(true);
      expect(result.data.message).toBe('Destination Unreachable: Fragmentation Needed and DF set');
      const duData = result.data.data as ICMPv4DestinationUnreachableData;
      expect(duData.nextHopMtu).toBe(1500);
      expect(duData.originalIpHeader.length).toBe(20);
      expect(duData.originalData.length).toBe(8);
    });
  });

  describe('Time Exceeded', () => {
    const originalPacketPart = Buffer.from([
      0x45, 0x00, 0x00, 0x28, 0xab, 0xcd, 0x00, 0x00, 0x01, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02,
      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ]);
    it('should decode Time Exceeded (TTL exceeded in Transit)', () => {
      const icmpPart = Buffer.from([0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Type 11, Code 0, Checksum placeholder, Unused
      const buffer = Buffer.concat([icmpPart, originalPacketPart]);
      const checksum = calculateICMPv4ChecksumForTest(buffer);
      buffer.writeUInt16BE(checksum, 2);

      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv4Layer>;
      expect(result.data.type).toBe(11);
      expect(result.data.code).toBe(0);
      expect(result.data.validChecksum).toBe(true);
      expect(result.data.message).toBe('Time Exceeded: Time to Live exceeded in Transit');
      const teData = result.data.data as ICMPv4TimeExceededData;
      expect(teData.unused.length).toBe(4);
      expect(teData.originalIpHeader.length).toBe(20);
      expect(teData.originalData.length).toBe(8);
    });
  });

  describe('Redirect', () => {
    const originalPacketPart = Buffer.from([
      0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
      0x08, 0x00, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    it('should decode Redirect (Redirect for Host)', () => {
      const icmpPart = Buffer.from([0x05, 0x01, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0xfe]); // Type 5, Code 1, Checksum placeholder, Gateway IP (192.168.1.254)
      const buffer = Buffer.concat([icmpPart, originalPacketPart]);
      const checksum = calculateICMPv4ChecksumForTest(buffer);
      buffer.writeUInt16BE(checksum, 2);

      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv4Layer>;
      expect(result.data.type).toBe(5);
      expect(result.data.code).toBe(1);
      expect(result.data.validChecksum).toBe(true);
      expect(result.data.message).toBe('Redirect: Redirect Datagrams for the Host');
      const rData = result.data.data as ICMPv4RedirectData;
      expect(rData.gatewayAddress).toBe('192.168.1.254');
      expect(rData.originalIpHeader.length).toBe(20);
      expect(rData.originalData.length).toBe(8);
    });
  });

  describe('Timestamp Request/Reply', () => {
    it('should decode Timestamp Request', () => {
      const buffer = Buffer.from([
        0x0d, 0x00, 0x00, 0x00, // Type 13, Code 0, Checksum placeholder
        0xba, 0xbe, 0xca, 0xfe, // Identifier, Sequence Number
        0x00, 0x00, 0x00, 0x01, // Originate Timestamp
        0x00, 0x00, 0x00, 0x00, // Receive Timestamp (0 for request)
        0x00, 0x00, 0x00, 0x00, // Transmit Timestamp (0 for request)
      ]);
      const checksum = calculateICMPv4ChecksumForTest(buffer);
      buffer.writeUInt16BE(checksum, 2);

      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv4Layer>;
      expect(result.data.type).toBe(13);
      expect(result.data.validChecksum).toBe(true);
      expect(result.data.message).toBe('Timestamp Request');
      const tsData = result.data.data as ICMPv4TimestampData;
      expect(tsData.identifier).toBe(0xbabe);
      expect(tsData.sequenceNumber).toBe(0xcafe);
      expect(tsData.originateTimestamp).toBe(1);
      expect(tsData.receiveTimestamp).toBe(0);
      expect(tsData.transmitTimestamp).toBe(0);
    });
  });

  describe('Address Mask Request/Reply', () => {
    it('should decode Address Mask Request', () => {
      const buffer = Buffer.from([
        0x11, 0x00, 0x00, 0x00, // Type 17, Code 0, Checksum placeholder
        0xde, 0xad, 0xbe, 0xef, // Identifier, Sequence Number
        0x00, 0x00, 0x00, 0x00, // Address Mask (0 for request)
      ]);
      const checksum = calculateICMPv4ChecksumForTest(buffer);
      buffer.writeUInt16BE(checksum, 2);

      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv4Layer>;
      expect(result.data.type).toBe(17);
      expect(result.data.validChecksum).toBe(true);
      expect(result.data.message).toBe('Address Mask Request');
      const amData = result.data.data as ICMPv4AddressMaskData;
      expect(amData.identifier).toBe(0xdead);
      expect(amData.sequenceNumber).toBe(0xbeef);
      expect(amData.addressMask).toBe('0.0.0.0');
    });

    it('should decode Address Mask Reply', () => {
        const buffer = Buffer.from([
          0x12, 0x00, 0x00, 0x00, // Type 18, Code 0, Checksum placeholder
          0xca, 0xfe, 0xba, 0xbe, // Identifier, Sequence Number
          0xff, 0xff, 0xff, 0x00, // Address Mask (255.255.255.0)
        ]);
        const checksum = calculateICMPv4ChecksumForTest(buffer);
        buffer.writeUInt16BE(checksum, 2);

        const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv4Layer>;
        expect(result.data.type).toBe(18);
        expect(result.data.validChecksum).toBe(true);
        expect(result.data.message).toBe('Address Mask Reply');
        const amData = result.data.data as ICMPv4AddressMaskData;
        expect(amData.identifier).toBe(0xcafe);
        expect(amData.sequenceNumber).toBe(0xbabe);
        expect(amData.addressMask).toBe('255.255.255.0');
      });
  });

  describe('Generic ICMP Data', () => {
    it('should handle unknown ICMP type as generic data', () => {
      const buffer = Buffer.from([
        0x28, 0x00, 0x00, 0x00, // Type 40 (example unknown), Code 0, Checksum placeholder
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Data
      ]);
      const checksum = calculateICMPv4ChecksumForTest(buffer);
      buffer.writeUInt16BE(checksum, 2);

      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv4Layer>;
      expect(result.data.type).toBe(40);
      expect(result.data.validChecksum).toBe(true);
      expect(result.data.message).toBe('Unknown ICMPv4 Type: 40');
      expect(result.data.data).toBeInstanceOf(Buffer);
      expect((result.data.data as Buffer).toString('hex')).toBe('0102030405060708');
    });
  });

  describe('Error Handling', () => {
    it('should throw BufferOutOfBoundsError for buffer smaller than base header', () => {
      const buffer = Buffer.from([0x08, 0x00, 0xf7]); // Only 3 bytes
      expect(() => decoder.decode(buffer)).toThrow(BufferOutOfBoundsError);
      expect(() => decoder.decode(buffer)).toThrow(
        'Buffer too small for ICMPv4 base header. Expected at least 4 bytes, got 3.',
      );
    });

    it('should throw PcapDecodingError for invalid checksum', () => {
      const buffer = Buffer.from([
        0x08, 0x00, 0x12, 0x34, // Type 8, Code 0, INVALID Checksum
        0xab, 0xcd, 0xef, 0x01,
        0x61, 0x62, 0x63, 0x64,
      ]);
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow(/Invalid ICMPv4 checksum/);
    });
  });

  describe('Parameter Problem', () => {
    const originalPacketPart = Buffer.from([
      // IP Header (20 bytes)
      0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x01, 0xac, 0x10, 0x0a, 0x02,
      // Original Data (8 bytes)
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ]);

    it('should decode Parameter Problem', () => {
      const icmpPart = Buffer.from([
        0x0c, 0x00, 0x00, 0x00, // Type 12, Code 0, Checksum placeholder
        0x05, 0x00, 0x00, 0x00, // Pointer (5), Unused
      ]);
      const buffer = Buffer.concat([icmpPart, originalPacketPart]);
      const checksum = calculateICMPv4ChecksumForTest(buffer);
      buffer.writeUInt16BE(checksum, 2);

      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv4Layer>;
      expect(result.data.type).toBe(12);
      expect(result.data.code).toBe(0);
      expect(result.data.message).toBe('Parameter Problem: Code 0');
      expect(result.data.validChecksum).toBe(true);
      const ppData = result.data.data as ICMPv4ParameterProblemData;
      expect(ppData.pointer).toBe(5);
      expect(ppData.unusedOrSpecific?.length).toBe(3); // 3 unused bytes
      expect(ppData.originalIpHeader.length).toBe(20);
      expect(ppData.originalData.length).toBe(8);
    });

    it('should throw BufferOutOfBoundsError for too short Parameter Problem', () => {
      const rawBuffer = Buffer.from([0x0c, 0x00, 0x00, 0x00, 0x01]); // Type, Code, Checksum, Pointer (missing unused and IP header)
      const checksum = calculateICMPv4ChecksumForTest(rawBuffer);
      rawBuffer.writeUInt16BE(checksum,2);
      expect(() => decoder.decode(rawBuffer)).toThrow(BufferOutOfBoundsError);
    });
  });

  describe('Router Solicitation', () => {
    it('should decode Router Solicitation', () => {
      const buffer = Buffer.from([
        0x0a, 0x00, 0x00, 0x00, // Type 10, Code 0, Checksum placeholder
        0x00, 0x00, 0x00, 0x00, // Reserved
      ]);
      const checksum = calculateICMPv4ChecksumForTest(buffer);
      buffer.writeUInt16BE(checksum, 2);

      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv4Layer>;
      expect(result.data.type).toBe(10);
      expect(result.data.code).toBe(0);
      expect(result.data.message).toBe('Router Solicitation');
      expect(result.data.validChecksum).toBe(true);
      const rsData = result.data.data as ICMPv4RouterSolicitationData;
      expect(rsData.reserved.length).toBe(4);
      expect(rsData.reserved.every(byte => byte === 0)).toBe(true);
    });
  });

  describe('Router Advertisement', () => {
    it('should decode Router Advertisement with one entry', () => {
      const buffer = Buffer.from([
        0x09, 0x00, 0x00, 0x00, // Type 9, Code 0, Checksum placeholder
        0x01, 0x02, 0x07, 0x08, // Num Addrs (1), Addr Entry Size (2 = 8 bytes), Lifetime (1800s)
        0xc0, 0xa8, 0x01, 0x01, // Router Address 1 (192.168.1.1)
        0x00, 0x00, 0x00, 0x0a, // Preference Level 1 (10)
      ]);
      const checksum = calculateICMPv4ChecksumForTest(buffer);
      buffer.writeUInt16BE(checksum, 2);

      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv4Layer>;
      expect(result.data.type).toBe(9);
      expect(result.data.code).toBe(0);
      expect(result.data.message).toBe('Router Advertisement');
      expect(result.data.validChecksum).toBe(true);
      const raData = result.data.data as ICMPv4RouterAdvertisementData;
      expect(raData.numAddrs).toBe(1);
      expect(raData.addrEntrySize).toBe(2);
      expect(raData.lifetime).toBe(1800);
      expect(raData.addresses.length).toBe(1);
      expect(raData.addresses[0].routerAddress).toBe('192.168.1.1');
      expect(raData.addresses[0].preferenceLevel).toBe(10);
    });

    it('should throw PcapDecodingError for invalid Addr Entry Size in Router Advertisement', () => {
      const buffer = Buffer.from([
        0x09, 0x00, 0x00, 0x00, // Type 9, Code 0, Checksum placeholder
        0x01, 0x01, 0x07, 0x08, // Num Addrs (1), Addr Entry Size (1 - INVALID), Lifetime
        0xc0, 0xa8, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x0a,
      ]);
      const checksum = calculateICMPv4ChecksumForTest(buffer);
      buffer.writeUInt16BE(checksum, 2);
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow('Invalid address entry size in Router Advertisement: 1. Expected 2.');
    });

     it('should throw BufferOutOfBoundsError for too short Router Advertisement (entries)', () => {
      const buffer = Buffer.from([
        0x09, 0x00, 0x00, 0x00, // Type 9, Code 0, Checksum placeholder
        0x01, 0x02, 0x07, 0x08, // Num Addrs (1), Addr Entry Size (2), Lifetime
        0xc0, 0xa8, 0x01,       // Incomplete entry
      ]);
      const checksum = calculateICMPv4ChecksumForTest(buffer);
      buffer.writeUInt16BE(checksum, 2);
      expect(() => decoder.decode(buffer)).toThrow(BufferOutOfBoundsError);
    });
  });


  describe('nextProtocolType', () => {
    it('should return null', () => {
      const dummyLayer: ICMPv4Layer = {
        type: 0,
        code: 0,
        checksum: 0,
        data: Buffer.alloc(0),
        validChecksum: true,
      };
      expect(decoder.nextProtocolType(dummyLayer)).toBeNull();
    });
  });
});
