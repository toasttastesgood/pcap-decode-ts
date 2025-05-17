import { describe, it, expect, beforeEach } from 'vitest';
import { Buffer } from 'buffer';
import { ICMPv6Decoder } from '../../../decode/icmpv6/icmpv6-decoder';
import {
  ICMPv6Layer,
  ICMPv6EchoData,
  ICMPv6DestinationUnreachableData,
  ICMPv6PacketTooBigData,
  ICMPv6TimeExceededData,
  ICMPv6ParameterProblemData,
  ICMPv6RouterSolicitationData,
  ICMPv6RouterAdvertisementData,
  ICMPv6NeighborSolicitationData,
  ICMPv6NeighborAdvertisementData,
  ICMPv6RedirectData,
  ICMPv6Option,
} from '../../../decode/icmpv6/icmpv6-layer';
import { BufferOutOfBoundsError, PcapDecodingError } from '../../../errors';
import { DecoderOutputLayer } from '../../../decode/decoder';

describe('ICMPv6Decoder', () => {
  let decoder: ICMPv6Decoder;

  beforeEach(() => {
    decoder = new ICMPv6Decoder();
  });

  it('should have the correct protocolName', () => {
    expect(decoder.protocolName).toBe('ICMPv6');
  });

  describe('Echo Request/Reply', () => {
    it('should correctly decode an Echo Request', () => {
      const buffer = Buffer.from([
        128, 0, 0x27, 0xfb, // Type 128 (Echo Request), Code 0, Checksum
        0x12, 0x34, 0x56, 0x78, // Identifier, Sequence Number
        0x61, 0x62, 0x63, 0x64, // Data ("abcd")
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv6Layer>;
      expect(result.data.type).toBe(128);
      expect(result.data.code).toBe(0);
      expect(result.data.checksum).toBe(0x27fb);
      expect(result.data.message).toBe('Echo Request');
      const echoData = result.data.data as ICMPv6EchoData;
      expect(echoData.identifier).toBe(0x1234);
      expect(echoData.sequenceNumber).toBe(0x5678);
      expect(echoData.echoData.toString('ascii')).toBe('abcd');
      expect(result.headerLength).toBe(buffer.length);
    });

    it('should correctly decode an Echo Reply', () => {
      const buffer = Buffer.from([
        129, 0, 0x26, 0xfb, // Type 129 (Echo Reply), Code 0, Checksum
        0xab, 0xcd, 0xef, 0x01, // Identifier, Sequence Number
        0x68, 0x65, 0x6c, 0x6c, 0x6f, // Data ("hello")
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv6Layer>;
      expect(result.data.type).toBe(129);
      const echoData = result.data.data as ICMPv6EchoData;
      expect(echoData.identifier).toBe(0xabcd);
      expect(echoData.sequenceNumber).toBe(0xef01);
      expect(echoData.echoData.toString('ascii')).toBe('hello');
    });

    it('should throw for too short Echo Request body', () => {
      const buffer = Buffer.from([128, 0, 0, 0, 1, 2]); // Body only 2 bytes
      expect(() => decoder.decode(buffer)).toThrow(BufferOutOfBoundsError);
    });
  });

  describe('Destination Unreachable', () => {
    const originalPacket = Buffer.from('original packet data, at least some part of it');
    it('should decode Destination Unreachable (No route)', () => {
      const buffer = Buffer.concat([
        Buffer.from([1, 0, 0, 0, 0, 0, 0, 0]), // Type 1, Code 0, Checksum, Unused
        originalPacket,
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv6Layer>;
      expect(result.data.type).toBe(1);
      expect(result.data.code).toBe(0);
      expect(result.data.message).toBe('Destination Unreachable: No route to destination');
      const duData = result.data.data as ICMPv6DestinationUnreachableData;
      expect(duData.unused.length).toBe(4);
      expect(duData.originalPacketData.toString('ascii')).toBe(originalPacket.toString('ascii'));
    });
  });

  describe('Packet Too Big', () => {
    const originalPacket = Buffer.from('original packet data for too big');
    it('should decode Packet Too Big', () => {
      const buffer = Buffer.concat([
        Buffer.from([2, 0, 0, 0, 0, 0, 0x05, 0xdc]), // Type 2, Code 0, Checksum, MTU (1500)
        originalPacket,
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv6Layer>;
      expect(result.data.type).toBe(2);
      expect(result.data.message).toBe('Packet Too Big');
      const ptbData = result.data.data as ICMPv6PacketTooBigData;
      expect(ptbData.mtu).toBe(1500);
      expect(ptbData.originalPacketData.toString('ascii')).toBe(originalPacket.toString('ascii'));
    });
  });

  describe('Time Exceeded', () => {
    const originalPacket = Buffer.from('original for time exceeded');
    it('should decode Time Exceeded (Hop limit)', () => {
      const buffer = Buffer.concat([
        Buffer.from([3, 0, 0, 0, 0, 0, 0, 0]), // Type 3, Code 0, Checksum, Unused
        originalPacket,
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv6Layer>;
      expect(result.data.type).toBe(3);
      expect(result.data.code).toBe(0);
      expect(result.data.message).toBe('Time Exceeded: Hop limit exceeded in transit');
      const teData = result.data.data as ICMPv6TimeExceededData;
      expect(teData.unused.length).toBe(4);
      expect(teData.originalPacketData.toString('ascii')).toBe(originalPacket.toString('ascii'));
    });
  });

  describe('Parameter Problem', () => {
    const originalPacket = Buffer.from('original for param problem');
    it('should decode Parameter Problem (Erroneous header field)', () => {
      const buffer = Buffer.concat([
        Buffer.from([4, 0, 0, 0, 0, 0, 0, 0x10]), // Type 4, Code 0, Checksum, Pointer (16)
        originalPacket,
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv6Layer>;
      expect(result.data.type).toBe(4);
      expect(result.data.code).toBe(0);
      expect(result.data.message).toBe('Parameter Problem: Erroneous header field encountered');
      const ppData = result.data.data as ICMPv6ParameterProblemData;
      expect(ppData.pointer).toBe(16);
      expect(ppData.originalPacketData.toString('ascii')).toBe(originalPacket.toString('ascii'));
    });
  });

  // NDP Tests
  describe('Router Solicitation', () => {
    it('should decode Router Solicitation with Source LLA option', () => {
      const buffer = Buffer.from([
        133, 0, 0, 0, // Type, Code, Checksum
        0, 0, 0, 0,   // Reserved
        1, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Option: Type 1 (SLLA), Length 1 (8 bytes), MAC
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv6Layer>;
      expect(result.data.type).toBe(133);
      const rsData = result.data.data as ICMPv6RouterSolicitationData;
      expect(rsData.reserved.length).toBe(4);
      expect(rsData.options.length).toBe(1);
      expect(rsData.options[0].type).toBe(1);
      expect(rsData.options[0].length).toBe(1);
      expect(rsData.options[0].linkLayerAddress).toBe('00:11:22:33:44:55');
    });
  });

  describe('Router Advertisement', () => {
    it('should decode Router Advertisement with MTU option', () => {
      const buffer = Buffer.from([
        134, 0, 0, 0, // Type, Code, Checksum
        64, 0x80, 0x07, 0x08, // Hop Limit (64), Flags (M=1, O=0), Router Lifetime (1800s)
        0, 0, 0x0b, 0xb8,   // Reachable Time (3000ms)
        0, 0, 0x03, 0xe8,   // Retrans Timer (1000ms)
        5, 1, 0, 0, 0, 0, 0x05, 0xdc, // Option: Type 5 (MTU), Length 1, Reserved, MTU (1500)
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv6Layer>;
      expect(result.data.type).toBe(134);
      const raData = result.data.data as ICMPv6RouterAdvertisementData;
      expect(raData.currentHopLimit).toBe(64);
      expect(raData.flags.M).toBe(true);
      expect(raData.flags.O).toBe(false);
      expect(raData.routerLifetime).toBe(1800);
      expect(raData.reachableTime).toBe(3000);
      expect(raData.retransTimer).toBe(1000);
      expect(raData.options.length).toBe(1);
      expect(raData.options[0].type).toBe(5);
      expect(raData.options[0].mtu).toBe(1500);
    });
  });

  describe('Neighbor Solicitation', () => {
    it('should decode Neighbor Solicitation', () => {
      const buffer = Buffer.from([
        135, 0, 0, 0, // Type, Code, Checksum
        0, 0, 0, 0,   // Reserved
        0xfe, 0x80, 0,0, 0,0,0,0, 0x02,0x02,0xb3,0xff,0xfe,0x1e,0x83,0x29, // Target Address
        // No options
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv6Layer>;
      expect(result.data.type).toBe(135);
      const nsData = result.data.data as ICMPv6NeighborSolicitationData;
      expect(nsData.targetAddress).toBe('fe80::202:b3ff:fe1e:8329');
      expect(nsData.options.length).toBe(0);
    });
  });

  describe('Neighbor Advertisement', () => {
    it('should decode Neighbor Advertisement with Target LLA', () => {
      const buffer = Buffer.from([
        136, 0, 0, 0, // Type, Code, Checksum
        0x60, 0, 0, 0, // Flags (R=0, S=1, O=1), Reserved
        0xfe, 0x80, 0,0, 0,0,0,0, 0x02,0x02,0xb3,0xff,0xfe,0x1e,0x83,0x29, // Target Address
        2, 1, 0x00, 0x0c, 0x29, 0x3a, 0x4b, 0x5c, // Option: Type 2 (TLLA), Length 1, MAC
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv6Layer>;
      expect(result.data.type).toBe(136);
      const naData = result.data.data as ICMPv6NeighborAdvertisementData;
      expect(naData.flags.R).toBe(false);
      expect(naData.flags.S).toBe(true);
      expect(naData.flags.O).toBe(true);
      expect(naData.targetAddress).toBe('fe80::202:b3ff:fe1e:8329');
      expect(naData.options.length).toBe(1);
      expect(naData.options[0].type).toBe(2);
      expect(naData.options[0].linkLayerAddress).toBe('00:0c:29:3a:4b:5c');
    });
  });
  
  describe('Redirect Message', () => {
    it('should decode Redirect message', () => {
        const buffer = Buffer.from([
            137, 0, 0, 0, // Type, Code, Checksum
            0, 0, 0, 0,   // Reserved
            // Target Address: 2001:db8:cafe:1::1
            0x20,0x01,0x0d,0xb8,0xca,0xfe,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
            // Destination Address: 2001:db8:cafe:2::2
            0x20,0x01,0x0d,0xb8,0xca,0xfe,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,
            // No options
        ]);
        const result = decoder.decode(buffer) as DecoderOutputLayer<ICMPv6Layer>;
        expect(result.data.type).toBe(137);
        const rData = result.data.data as ICMPv6RedirectData;
        expect(rData.targetAddress).toBe('2001:db8:cafe:1::1');
        expect(rData.destinationAddress).toBe('2001:db8:cafe:2::2');
        expect(rData.options.length).toBe(0);
    });
  });


  describe('Error Handling', () => {
    it('should throw BufferOutOfBoundsError for too small buffer', () => {
      const buffer = Buffer.from([128, 0, 0]); // 3 bytes
      expect(() => decoder.decode(buffer)).toThrow(BufferOutOfBoundsError);
    });

    it('should throw PcapDecodingError for option with length 0', () => {
        const buffer = Buffer.from([
            133, 0, 0, 0, // Router Solicitation
            0,0,0,0,       // Reserved
            1, 0,           // Option: Type 1, Length 0 (invalid)
        ]);
        expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
        expect(() => decoder.decode(buffer)).toThrow('ICMPv6 option has invalid length 0 at offset 0');
    });

     it('should throw BufferOutOfBoundsError for option exceeding buffer', () => {
        const buffer = Buffer.from([
            133, 0, 0, 0, // Router Solicitation
            0,0,0,0,       // Reserved
            1, 2, 0x11,0x22,0x33,0x44,0x55,0x66, // Option: Type 1, Length 2 (16 bytes), but only 6 data bytes provided after type/len
        ]);
         expect(() => decoder.decode(buffer)).toThrow(BufferOutOfBoundsError);
         expect(() => decoder.decode(buffer)).toThrow('ICMPv6 option (type 1, length 16) at offset 0 exceeds buffer bounds.');
    });
  });

  describe('nextProtocolType', () => {
    it('should return null', () => {
      const dummyLayer: ICMPv6Layer = { type: 128, code: 0, checksum: 0, data: Buffer.alloc(0) };
      expect(decoder.nextProtocolType(dummyLayer)).toBeNull();
    });
  });
});
