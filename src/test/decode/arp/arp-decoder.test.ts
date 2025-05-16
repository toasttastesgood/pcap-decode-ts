import { describe, it, expect, beforeEach } from 'vitest';
import { ARPDecoder, ARPLayer } from '../../../decode/arp/arp-decoder';
import { BufferOutOfBoundsError } from '../../../errors';
import { DecoderOutputLayer } from '../../../decode/decoder';

describe('ARPDecoder', () => {
  let decoder: ARPDecoder;

  beforeEach(() => {
    decoder = new ARPDecoder();
  });

  it('should have the correct protocolName', () => {
    expect(decoder.protocolName).toBe('ARP');
  });

  describe('decode', () => {
    // Sample ARP Request:
    // Hardware Type: Ethernet (1) - 2 bytes
    // Protocol Type: IPv4 (0x0800) - 2 bytes
    // Hardware Address Length: 6 - 1 byte
    // Protocol Address Length: 4 - 1 byte
    // Opcode: Request (1) - 2 bytes
    // Sender MAC: 00:50:56:c0:00:08 - 6 bytes
    // Sender IP: 192.168.1.100 - 4 bytes
    // Target MAC: 00:00:00:00:00:00 - 6 bytes (unknown)
    // Target IP: 192.168.1.1 - 4 bytes
    const arpRequestBuffer = Buffer.from([
      0x00,
      0x01, // Hardware Type: Ethernet
      0x08,
      0x00, // Protocol Type: IPv4
      0x06, // Hardware Address Length
      0x04, // Protocol Address Length
      0x00,
      0x01, // Opcode: Request
      0x00,
      0x50,
      0x56,
      0xc0,
      0x00,
      0x08, // Sender MAC
      192,
      168,
      1,
      100, // Sender IP
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00, // Target MAC
      192,
      168,
      1,
      1, // Target IP
    ]);

    // Sample ARP Reply:
    // Hardware Type: Ethernet (1)
    // Protocol Type: IPv4 (0x0800)
    // Hardware Address Length: 6
    // Protocol Address Length: 4
    // Opcode: Reply (2)
    // Sender MAC: 00:0c:29:eb:5e:3c (MAC of 192.168.1.1)
    // Sender IP: 192.168.1.1
    // Target MAC: 00:50:56:c0:00:08 (MAC of 192.168.1.100)
    // Target IP: 192.168.1.100
    const arpReplyBuffer = Buffer.from([
      0x00,
      0x01, // Hardware Type: Ethernet
      0x08,
      0x00, // Protocol Type: IPv4
      0x06, // Hardware Address Length
      0x04, // Protocol Address Length
      0x00,
      0x02, // Opcode: Reply
      0x00,
      0x0c,
      0x29,
      0xeb,
      0x5e,
      0x3c, // Sender MAC
      192,
      168,
      1,
      1, // Sender IP
      0x00,
      0x50,
      0x56,
      0xc0,
      0x00,
      0x08, // Target MAC
      192,
      168,
      1,
      100, // Target IP
    ]);

    it('should correctly decode an ARP request packet', () => {
      const decoded = decoder.decode(arpRequestBuffer) as DecoderOutputLayer<ARPLayer>;

      expect(decoded).not.toBeNull();
      expect(decoded.protocolName).toBe('ARP');
      expect(decoded.headerLength).toBe(28);
      expect(decoded.payload.length).toBe(0);

      const data = decoded.data;
      expect(data.hardwareType).toBe(1); // Ethernet
      expect(data.protocolType).toBe(0x0800); // IPv4
      expect(data.hardwareAddressLength).toBe(6);
      expect(data.protocolAddressLength).toBe(4);
      expect(data.opcode).toBe(1); // Request
      expect(data.senderMac).toBe('00:50:56:c0:00:08');
      expect(data.senderIp).toBe('192.168.1.100');
      expect(data.targetMac).toBe('00:00:00:00:00:00');
      expect(data.targetIp).toBe('192.168.1.1');
    });

    it('should correctly decode an ARP reply packet', () => {
      const decoded = decoder.decode(arpReplyBuffer) as DecoderOutputLayer<ARPLayer>;

      expect(decoded).not.toBeNull();
      expect(decoded.protocolName).toBe('ARP');
      expect(decoded.headerLength).toBe(28);
      expect(decoded.payload.length).toBe(0);

      const data = decoded.data;
      expect(data.hardwareType).toBe(1); // Ethernet
      expect(data.protocolType).toBe(0x0800); // IPv4
      expect(data.hardwareAddressLength).toBe(6);
      expect(data.protocolAddressLength).toBe(4);
      expect(data.opcode).toBe(2); // Reply
      expect(data.senderMac).toBe('00:0c:29:eb:5e:3c');
      expect(data.senderIp).toBe('192.168.1.1');
      expect(data.targetMac).toBe('00:50:56:c0:00:08');
      expect(data.targetIp).toBe('192.168.1.100');
    });

    it('should throw BufferOutOfBoundsError if buffer is too small for fixed header fields', () => {
      const tooSmallBuffer = Buffer.from([0x00, 0x01, 0x08, 0x00, 0x06]); // Only 5 bytes
      expect(() => decoder.decode(tooSmallBuffer)).toThrow(BufferOutOfBoundsError);
      expect(() => decoder.decode(tooSmallBuffer)).toThrow(
        'Buffer too small for ARP header. Expected at least 8 bytes for fixed fields, got 5.',
      );
    });

    it('should throw BufferOutOfBoundsError if buffer is too small for declared address lengths', () => {
      // Valid fixed header, but not enough bytes for addresses
      const incompleteAddressBuffer = Buffer.from([
        0x00,
        0x01, // Hardware Type: Ethernet
        0x08,
        0x00, // Protocol Type: IPv4
        0x06, // Hardware Address Length (expects 6 bytes for MAC)
        0x04, // Protocol Address Length (expects 4 bytes for IP)
        0x00,
        0x01, // Opcode: Request
        0x00,
        0x50,
        0x56,
        0xc0,
        0x00,
        0x08, // Sender MAC (6 bytes)
        192,
        168,
        1,
        100, // Sender IP (4 bytes)
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // Target MAC (incomplete - 5 bytes instead of 6)
      ]);
      expect(() => decoder.decode(incompleteAddressBuffer)).toThrow(BufferOutOfBoundsError);
      // The buffer is 27 bytes long. The fixed header is 8 bytes.
      // The error message correctly reflects the available buffer length for addresses.
      // The buffer is 8 (fixed) + 6 (SMAC) + 4 (SIP) + 5 (TMAC) = 23 bytes.
      expect(() => decoder.decode(incompleteAddressBuffer)).toThrow(
        'Buffer too small for ARP packet. Expected 28 bytes based on hardware_addr_len=6 and protocol_addr_len=4, got 23. Current offset: 8.',
      );
    });
 
    it('should handle non-IPv4 protocol addresses by returning hex string', () => {
      const nonIPv4ArpBuffer = Buffer.from([
        0x00,
        0x01, // Hardware Type: Ethernet
        0x8035, // Protocol Type: RARP (Reverse ARP - example, not 0x0800)
        0x06, // Hardware Address Length
        0x04, // Protocol Address Length
        0x00,
        0x03, // Opcode: RARP Request
        0x00,
        0x50,
        0x56,
        0xc0,
        0x00,
        0x08,
        0x01,
        0x02,
        0x03,
        0x04, // Sender Protocol Address (4 bytes, but not IPv4 type)
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x05,
        0x06,
        0x07,
        0x08, // Target Protocol Address (4 bytes, but not IPv4 type)
      ]);
      const decoded = decoder.decode(nonIPv4ArpBuffer) as DecoderOutputLayer<ARPLayer>;
      expect(decoded.data.protocolType).toBe(0x8035);
      expect(decoded.data.senderIp).toBe('01020304'); // Fallback to hex
      expect(decoded.data.targetIp).toBe('05060708'); // Fallback to hex
    });

    it('should return null for nextProtocolType', () => {
      expect(decoder.nextProtocolType()).toBeNull();
    });
  });
});
