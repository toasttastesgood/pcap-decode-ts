import { Buffer } from 'buffer';
import { describe, it, expect } from 'vitest';
import { Ethernet2Decoder, Ethernet2Layer } from '../../../decode/ethernet/ethernet2-decoder';
import { BufferOutOfBoundsError } from '../../../errors';
import { DecoderOutputLayer } from '../../../decode/decoder';

describe('Ethernet2Decoder', () => {
  const decoder = new Ethernet2Decoder();

  it('should have the correct protocolName', () => {
    expect(decoder.protocolName).toBe('Ethernet II');
  });

  describe('decode', () => {
    it('should correctly decode a valid Ethernet II frame for IPv4', () => {
      // MAC Addresses:
      // Dest: AA:BB:CC:DD:EE:FF
      // Src:  00:11:22:33:44:55
      // EtherType: 0x0800 (IPv4)
      // Payload: 01 02 03 04
      const buffer = Buffer.from([
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xee,
        0xff, // Destination MAC
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55, // Source MAC
        0x08,
        0x00, // EtherType (IPv4)
        0x01,
        0x02,
        0x03,
        0x04, // Payload
      ]);

      const result = decoder.decode(buffer) as DecoderOutputLayer<Ethernet2Layer>;

      expect(result.protocolName).toBe('Ethernet II');
      expect(result.headerLength).toBe(14);
      expect(result.data.destinationMac).toBe('aa:bb:cc:dd:ee:ff');
      expect(result.data.sourceMac).toBe('00:11:22:33:44:55');
      expect(result.data.etherType).toBe(0x0800);
      expect(result.payload.toString('hex')).toBe('01020304');
    });

    it('should correctly decode a valid Ethernet II frame for ARP', () => {
      // EtherType: 0x0806 (ARP)
      const buffer = Buffer.from([
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff, // Destination MAC (Broadcast)
        0x12,
        0x34,
        0x56,
        0x78,
        0x9a,
        0xbc, // Source MAC
        0x08,
        0x06, // EtherType (ARP)
        0xde,
        0xad,
        0xbe,
        0xef, // Payload
      ]);

      const result = decoder.decode(buffer) as DecoderOutputLayer<Ethernet2Layer>;
 
      expect(result.data.destinationMac).toBe('ff:ff:ff:ff:ff:ff');
      expect(result.data.sourceMac).toBe('12:34:56:78:9a:bc');
      expect(result.data.etherType).toBe(0x0806);
      expect(result.payload.toString('hex')).toBe('deadbeef');
    });

    it('should correctly decode a valid Ethernet II frame for IPv6', () => {
      // EtherType: 0x86DD (IPv6)
      const buffer = Buffer.from([
        0x33,
        0x33,
        0x00,
        0x00,
        0x00,
        0x01, // Destination MAC (IPv6 Multicast)
        0xab,
        0xcd,
        0xef,
        0x12,
        0x34,
        0x56, // Source MAC
        0x86,
        0xdd, // EtherType (IPv6)
        0xca,
        0xfe, // Payload
      ]);

      const result = decoder.decode(buffer) as DecoderOutputLayer<Ethernet2Layer>;
 
      expect(result.data.destinationMac).toBe('33:33:00:00:00:01');
      expect(result.data.sourceMac).toBe('ab:cd:ef:12:34:56');
      expect(result.data.etherType).toBe(0x86dd);
      expect(result.payload.toString('hex')).toBe('cafe');
    });

    it('should throw BufferOutOfBoundsError if buffer is too small (e.g. 6 bytes)', () => {
      const buffer = Buffer.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // Only 6 bytes
      expect(() => decoder.decode(buffer)).toThrow(BufferOutOfBoundsError);
      expect(() => decoder.decode(buffer)).toThrow(
        'Buffer too small for Ethernet II header. Expected 14 bytes, got 6.',
      );
    });

    it('should throw BufferOutOfBoundsError if buffer is 1 byte short of header (13 bytes)', () => {
      const buffer = Buffer.from([
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08,
      ]); // 13 bytes
      expect(() => decoder.decode(buffer)).toThrow(BufferOutOfBoundsError);
      expect(() => decoder.decode(buffer)).toThrow(
        'Buffer too small for Ethernet II header. Expected 14 bytes, got 13.',
      );
    });

    it('should handle a buffer that is exactly 14 bytes (no payload)', () => {
      const buffer = Buffer.from([
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
      ]);
      const result = decoder.decode(buffer) as DecoderOutputLayer<Ethernet2Layer>;
      expect(result.data.etherType).toBe(0x0800);
      expect(result.payload.length).toBe(0);
      expect(result.payload.toString('hex')).toBe('');
    });

    it('should correctly decode a valid Ethernet II frame for Wake-on-LAN (WoL)', () => {
      // EtherType: 0x0842 (WoL)
      const buffer = Buffer.from([
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination MAC (Broadcast)
        0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, // Source MAC
        0x08, 0x42,                         // EtherType (WoL)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Payload (example WoL magic packet part)
      ]);

      const result = decoder.decode(buffer) as DecoderOutputLayer<Ethernet2Layer>;

      expect(result.data.destinationMac).toBe('ff:ff:ff:ff:ff:ff');
      expect(result.data.sourceMac).toBe('1a:2b:3c:4d:5e:6f');
      expect(result.data.etherType).toBe(0x0842);
      expect(result.payload.toString('hex')).toBe('010203040506');
    });

    it('should correctly decode a valid Ethernet II frame for LLDP', () => {
      // EtherType: 0x88CC (LLDP)
      // LLDP MAC: 01:80:c2:00:00:0e
      const buffer = Buffer.from([
        0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, // Destination MAC (LLDP Multicast)
        0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc, // Source MAC
        0x88, 0xcc,                         // EtherType (LLDP)
        0x02, 0x07, 0x04, 0x00, 0x11, 0x22, 0x33, // Payload (example LLDP data)
      ]);

      const result = decoder.decode(buffer) as DecoderOutputLayer<Ethernet2Layer>;

      expect(result.data.destinationMac).toBe('01:80:c2:00:00:0e');
      expect(result.data.sourceMac).toBe('11:22:33:aa:bb:cc');
      expect(result.data.etherType).toBe(0x88cc);
      expect(result.payload.toString('hex')).toBe('02070400112233');
    });
  });

  describe('nextProtocolType', () => {
    it('should return the etherType from the decoded layer data', () => {
      const decodedLayerData: Ethernet2Layer = {
        destinationMac: 'aa:bb:cc:dd:ee:ff',
        sourceMac: '00:11:22:33:44:55',
        etherType: 0x0800,
      };
      expect(decoder.nextProtocolType(decodedLayerData)).toBe(0x0800);
 
      const decodedLayerDataARP: Ethernet2Layer = {
        destinationMac: 'ff:ff:ff:ff:ff:ff',
        sourceMac: '12:34:56:78:9a:bc',
        etherType: 0x0806,
      };
      expect(decoder.nextProtocolType(decodedLayerDataARP)).toBe(0x0806);
    });
  });
});
