import { describe, it, expect } from 'vitest';
import {
  parseSectionHeaderBlock,
  parseInterfaceDescriptionBlock,
  parseEnhancedPacketBlock,
  parseNameResolutionBlock,
  parseOptions,
} from '../../pcapng/block-parsers';
import { PcapParsingError } from '../../errors';

// Mock data and helper functions will be added here

describe('PCAPng Block Parsers', () => {
  describe('parseOptions', () => {
    // Tests for parseOptions will be added here
    it('should correctly parse an empty options list (opt_endofopt)', () => {
      const buffer = Buffer.from([0x00, 0x00, 0x00, 0x00]); // opt_endofopt
      const options = parseOptions(buffer, true);
      expect(options).toEqual([]);
    });

    it('should correctly parse a single option', () => {
      // shb_hardware option: code 2, length 4, value "HW  "
      const buffer = Buffer.from([
        0x00,
        0x02, // Option Code: shb_hardware
        0x00,
        0x04, // Option Length: 4
        0x48,
        0x57,
        0x20,
        0x20, // Option Value: "HW  "
        0x00,
        0x00,
        0x00,
        0x00, // opt_endofopt
      ]);
      const options = parseOptions(buffer, true);
      expect(options).toHaveLength(1);
      expect(options[0].code).toBe(2);
      expect(options[0].length).toBe(4);
      expect(options[0].value).toEqual(Buffer.from([0x48, 0x57, 0x20, 0x20]));
    });

    it('should correctly parse multiple options with padding', () => {
      // Option 1: code 2, length 3, value "ABC" (padded to 4 bytes)
      // Option 2: code 3, length 5, value "DEFGH" (padded to 8 bytes)
      const buffer = Buffer.from([
        0x00,
        0x02,
        0x00,
        0x03,
        0x41,
        0x42,
        0x43,
        0x00, // Opt1 + padding
        0x00,
        0x03,
        0x00,
        0x05,
        0x44,
        0x45,
        0x46,
        0x47,
        0x48,
        0x00,
        0x00,
        0x00, // Opt2 + padding
        0x00,
        0x00,
        0x00,
        0x00, // opt_endofopt
      ]);
      const options = parseOptions(buffer, true);
      expect(options).toHaveLength(2);
      expect(options[0]).toEqual({ code: 2, length: 3, value: Buffer.from([0x41, 0x42, 0x43]) });
      expect(options[1]).toEqual({
        code: 3,
        length: 5,
        value: Buffer.from([0x44, 0x45, 0x46, 0x47, 0x48]),
      });
    });

    it('should throw PcapParsingError for option length exceeding buffer', () => {
      const buffer = Buffer.from([
        0x00,
        0x02, // Option Code
        0x00,
        0x0a, // Option Length: 10 (too long)
        0x41,
        0x42,
        0x43, // Only 3 bytes of value
      ]);
      expect(() => parseOptions(buffer, true)).toThrow(PcapParsingError);
      expect(() => parseOptions(buffer, true)).toThrow(
        'Option length 10 at offset 2 exceeds buffer bounds (buffer length 7).',
      );
    });
  });

  describe('parseSectionHeaderBlock (SHB)', () => {
    // Tests for SHB parser will be added here
    it('should correctly parse a valid SHB body (big-endian)', () => {
      const blockBody = Buffer.from([
        0x1a,
        0x2b,
        0x3c,
        0x4d, // Byte Order Magic
        0x00,
        0x01, // Major Version
        0x00,
        0x00, // Minor Version
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00, // Section Length (256)
        // Options: shb_hardware (code 2, len 3, "HW "), padded
        0x00,
        0x02,
        0x00,
        0x03,
        0x48,
        0x57,
        0x20,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // opt_endofopt
      ]);
      const isBigEndian = true; // Determined by generic parser from byte_order_magic
      const shb = parseSectionHeaderBlock(blockBody, isBigEndian);

      expect(shb.byte_order_magic).toBe(0x1a2b3c4d);
      expect(shb.major_version).toBe(1);
      expect(shb.minor_version).toBe(0);
      expect(shb.section_length).toBe(BigInt(256));
      expect(shb.options).toHaveLength(1);
      expect(shb.options[0]).toEqual({ code: 2, length: 3, value: Buffer.from('HW ') });
      // block_type and block_total_length are placeholders for now
      expect(shb.block_type).toBe(0x0a0d0d0a);
    });

    it('should correctly parse a valid SHB body (little-endian)', () => {
      const blockBody = Buffer.from([
        0x4d,
        0x3c,
        0x2b,
        0x1a, // Byte Order Magic (LE)
        0x01,
        0x00, // Major Version (LE)
        0x00,
        0x00, // Minor Version (LE)
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // Section Length (256 LE)
        // Options: shb_os (code 3, len 5, "Linux"), padded
        0x03,
        0x00,
        0x05,
        0x00,
        0x4c,
        0x69,
        0x6e,
        0x75,
        0x78,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // opt_endofopt
      ]);
      const isBigEndian = false;
      const shb = parseSectionHeaderBlock(blockBody, isBigEndian);

      expect(shb.byte_order_magic).toBe(0x1a2b3c4d);
      expect(shb.major_version).toBe(1);
      expect(shb.minor_version).toBe(0);
      expect(shb.section_length).toBe(BigInt(256));
      expect(shb.options).toHaveLength(1);
      expect(shb.options[0]).toEqual({ code: 3, length: 5, value: Buffer.from('Linux') });
      expect(shb.block_type).toBe(0x0a0d0d0a);
    });
  });

  describe('parseInterfaceDescriptionBlock (IDB)', () => {
    // Tests for IDB parser will be added here
    it('should correctly parse a valid IDB body (big-endian)', () => {
      const blockBody = Buffer.from([
        0x00,
        0x01, // LinkType (Ethernet)
        0x00,
        0x00, // Reserved
        0x00,
        0x00,
        0x05,
        0xdc, // SnapLen (1500)
        // Options: if_name (code 2, len 4, "eth0"), no padding needed
        0x00,
        0x02,
        0x00,
        0x04,
        0x65,
        0x74,
        0x68,
        0x30,
        0x00,
        0x00,
        0x00,
        0x00, // opt_endofopt
      ]);
      const isBigEndian = true;
      const idb = parseInterfaceDescriptionBlock(blockBody, isBigEndian);

      expect(idb.linktype).toBe(1);
      expect(idb.reserved).toBe(0);
      expect(idb.snaplen).toBe(1500);
      expect(idb.options).toHaveLength(1);
      expect(idb.options[0]).toEqual({ code: 2, length: 4, value: Buffer.from('eth0') });
      expect(idb.block_type).toBe(0x00000001);
    });
  });

  describe('parseEnhancedPacketBlock (EPB)', () => {
    // Tests for EPB parser will be added here
    it('should correctly parse a valid EPB body (little-endian)', () => {
      const blockBody = Buffer.from([
        0x00,
        0x00,
        0x00,
        0x00, // Interface ID (0)
        0xcd,
        0xab,
        0x00,
        0x00, // Timestamp (High)
        0xef,
        0xbe,
        0xad,
        0xde, // Timestamp (Low)
        0x0a,
        0x00,
        0x00,
        0x00, // Captured Len (10)
        0x0a,
        0x00,
        0x00,
        0x00, // Original Len (10)
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a, // Packet Data (10 bytes)
        0x00,
        0x00, // Padding for Packet Data (to 12 bytes)
        // Options: epb_flags (code 2, len 4, value 0x00000001)
        0x02,
        0x00,
        0x04,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00, // opt_endofopt
      ]);
      const isBigEndian = false;
      const epb = parseEnhancedPacketBlock(blockBody, isBigEndian);

      expect(epb.interface_id).toBe(0);
      expect(epb.timestamp_high).toBe(0xabcd);
      expect(epb.timestamp_low).toBe(0xdeadbeef);
      expect(epb.captured_len).toBe(10);
      expect(epb.original_len).toBe(10);
      expect(epb.packet_data).toEqual(
        Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a]),
      );
      expect(epb.options).toHaveLength(1);
      expect(epb.options[0]).toEqual({
        code: 2,
        length: 4,
        value: Buffer.from([0x01, 0x00, 0x00, 0x00]),
      });
      expect(epb.block_type).toBe(0x00000006);
    });

    it('should throw PcapParsingError for EPB captured length exceeding block body', () => {
      const blockBody = Buffer.from([
        0x00,
        0x00,
        0x00,
        0x00, // Interface ID (0)
        0xcd,
        0xab,
        0x00,
        0x00, // Timestamp (High)
        0xef,
        0xbe,
        0xad,
        0xde, // Timestamp (Low)
        0xff,
        0x00,
        0x00,
        0x00, // Captured Len (255 - too large)
        0x0a,
        0x00,
        0x00,
        0x00, // Original Len (10)
        0x01,
        0x02,
        0x03,
        0x04,
        0x05, // Only 5 bytes of data
      ]);
      expect(() => parseEnhancedPacketBlock(blockBody, false)).toThrow(PcapParsingError);
      expect(() => parseEnhancedPacketBlock(blockBody, false)).toThrow(
        'EPB captured_len (255) at offset 16 exceeds block body bounds (blockBody length 25).',
      );
    });

    it('should throw PcapParsingError for EPB offset exceeding block body before options', () => {
      // Construct a blockBody where captured_len and padding are such that
      // the offset for options is beyond the blockBody length.
      // Header (20 bytes: if_id(4) + ts_high(4) + ts_low(4) + cap_len(4) + orig_len(4))
      // Suppose captured_len is 5, padding is 3 (total 8 for data part)
      // Options start after 20 + 8 = 28.
      // If blockBody is only 27 bytes long.
      const epbBlockBodyTooShortForOptions = Buffer.from([
        // Renamed variable
        0x00,
        0x00,
        0x00,
        0x00, // Interface ID (0)
        0x00,
        0x00,
        0x00,
        0x00, // Timestamp (High)
        0x00,
        0x00,
        0x00,
        0x00, // Timestamp (Low)
        0x05,
        0x00,
        0x00,
        0x00, // Captured Len (5)
        0x05,
        0x00,
        0x00,
        0x00, // Original Len (5)
        0x01,
        0x02,
        0x03,
        0x04,
        0x05, // Packet Data (5 bytes)
        0x00,
        0x00, // Missing one byte of padding and any options
      ]); // Total 27 bytes. Expected options offset is 20 (fixed) + 5 (cap) + 3 (pad) = 28.
      expect(() => parseEnhancedPacketBlock(epbBlockBodyTooShortForOptions, false)).toThrow(
        PcapParsingError,
      );
      expect(() => parseEnhancedPacketBlock(epbBlockBodyTooShortForOptions, false)).toThrow(
        'EPB offset (28) exceeds block body bounds (blockBody length 27) before parsing options.',
      );
    });
  });

  describe('parseNameResolutionBlock (NRB)', () => {
    // Tests for NRB parser will be added here
    it('should correctly parse a valid NRB body with IPv4 and IPv6 records (big-endian)', () => {
      const blockBody = Buffer.from([
        // Record 1: IPv4 (type 1), len 14 (4 for IP + 10 for "host.com\0")
        0x00,
        0x01,
        0x00,
        0x0e, // Type, Length
        0xc0,
        0xa8,
        0x00,
        0x01, // 192.168.0.1
        0x68,
        0x6f,
        0x73,
        0x74,
        0x2e,
        0x63,
        0x6f,
        0x6d,
        0x00, // "host.com"
        0x00, // Null terminator for name
        0x00,
        0x00, // Padding for record (to 16 bytes total for record data)
        // Record 2: IPv6 (type 2), len 28 (16 for IP + 12 for "router.lan\0")
        0x00,
        0x02,
        0x00,
        0x1c, // Type, Length
        0x20,
        0x01,
        0x0d,
        0xb8,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01, // ::1
        0x72,
        0x6f,
        0x75,
        0x74,
        0x65,
        0x72,
        0x2e,
        0x6c,
        0x61,
        0x6e,
        0x00, // "router.lan"
        0x00, // Null terminator for name
        // No padding needed for this record as 4+28 = 32
        0x00,
        0x00,
        0x00,
        0x00, // nrb_record_end
        // Options: ns_dnsname (code 2, len 9, "dns.server"), padded
        0x00,
        0x02,
        0x00,
        0x09,
        0x64,
        0x6e,
        0x73,
        0x2e,
        0x73,
        0x65,
        0x72,
        0x76,
        0x65,
        0x72,
        0x00,
        0x00, // value + padding
        0x00,
        0x00,
        0x00,
        0x00, // opt_endofopt
      ]);
      const isBigEndian = true;
      const nrb = parseNameResolutionBlock(blockBody, isBigEndian);

      expect(nrb.records).toHaveLength(2);
      expect(nrb.records[0].record_type).toBe(1); // IPv4
      expect(nrb.records[0].record_value_length).toBe(14);
      expect(nrb.records[0].record_value).toEqual(
        Buffer.from([
          0xc0, 0xa8, 0x00, 0x01, 0x68, 0x6f, 0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
        ]),
      );

      expect(nrb.records[1].record_type).toBe(2); // IPv6
      expect(nrb.records[1].record_value_length).toBe(28);
      expect(nrb.records[1].record_value.slice(0, 16)).toEqual(
        Buffer.from([
          0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x01,
        ]),
      );
      expect(nrb.records[1].record_value.slice(16)).toEqual(Buffer.from('router.lan\0\0')); // Includes the two nulls

      expect(nrb.options).toHaveLength(1);
      expect(nrb.options[0]).toEqual({ code: 2, length: 9, value: Buffer.from('dns.server') });
      expect(nrb.block_type).toBe(0x00000004);
    });

    it('should correctly parse an NRB with no records, only options', () => {
      const blockBody = Buffer.from([
        0x00,
        0x00,
        0x00,
        0x00, // nrb_record_end
        // Options: ns_dnsname (code 2, len 9, "dns.server"), padded
        0x00,
        0x02,
        0x00,
        0x09,
        0x64,
        0x6e,
        0x73,
        0x2e,
        0x73,
        0x65,
        0x72,
        0x76,
        0x65,
        0x72,
        0x00,
        0x00, // value + padding
        0x00,
        0x00,
        0x00,
        0x00, // opt_endofopt
      ]);
      const isBigEndian = true;
      const nrb = parseNameResolutionBlock(blockBody, isBigEndian);
      expect(nrb.records).toHaveLength(0);
      expect(nrb.options).toHaveLength(1);
      expect(nrb.options[0]).toEqual({ code: 2, length: 9, value: Buffer.from('dns.server') });
    });

    it('should throw PcapParsingError for NRB record value length exceeding block body', () => {
      const blockBody = Buffer.from([
        0x00,
        0x01,
        0x00,
        0xff, // Type, Length (255 - too large)
        0xc0,
        0xa8,
        0x00,
        0x01, // Only 4 bytes of data
      ]);
      expect(() => parseNameResolutionBlock(blockBody, true)).toThrow(PcapParsingError);
      expect(() => parseNameResolutionBlock(blockBody, true)).toThrow(
        'NRB record_value_length (255) at offset 2 for record_type 1 exceeds block body bounds (blockBody length 6).',
      );
    });

    it('should throw PcapParsingError for NRB offset exceeding block body before options', () => {
      // Construct a blockBody where records and padding are such that
      // the offset for options is beyond the blockBody length.
      // Record 1: type 1, len 1 (value 'A'), padded to 4. Total 2+2+1+1 = 6 bytes for record part.
      // If blockBody is only 5 bytes long after nrb_record_end.
      // More precise:
      // Record: Type (2B), Length (2B), Value (1B) = 5B. Padded to 8B (record_data_length = 4+1=5, pad=3).
      // nrb_record_end (4B)
      // Total before options = 8 + 4 = 12.
      // If buffer is 11.
      const recordData = [0x00, 0x01, 0x00, 0x01, 0x41, 0x00, 0x00, 0x00]; // Record1 (padded)
      const recordEnd = [0x00, 0x00, 0x00, 0x00]; // nrb_record_end
      const fullBlockUpToOptions = Buffer.concat([Buffer.from(recordData), Buffer.from(recordEnd)]); // 12 bytes

      const bodyEndsBeforeOptionsCanStart = fullBlockUpToOptions.subarray(0, 11); // 11 bytes long

      expect(() => parseNameResolutionBlock(bodyEndsBeforeOptionsCanStart, true)).toThrow(
        PcapParsingError,
      );
      expect(() => parseNameResolutionBlock(bodyEndsBeforeOptionsCanStart, true)).toThrow(
        'NRB offset (12) exceeds block body bounds (blockBody length 11) before parsing options.',
      );
    });
  });
});
