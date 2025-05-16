import { describe, test, expect } from 'vitest';
import { Buffer } from 'buffer';
import { parsePcapPacketRecord } from '../../pcap/packet-record-parser';
import { PcapParsingError } from '../../errors';

describe('parsePcapPacketRecord', () => {
  // Test data for a simple packet record
  const ts_sec_le = Buffer.from([0x61, 0x62, 0x63, 0x64]); // 1684234849 in LE
  const ts_usec_le = Buffer.from([0x01, 0x02, 0x03, 0x04]); // 67305985 in LE
  const incl_len_le = Buffer.from([0x04, 0x00, 0x00, 0x00]); // 4 in LE
  const orig_len_le = Buffer.from([0x08, 0x00, 0x00, 0x00]); // 8 in LE
  const packet_data_le = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  const sampleRecordLE = Buffer.concat([
    ts_sec_le,
    ts_usec_le,
    incl_len_le,
    orig_len_le,
    packet_data_le,
  ]);

  const ts_sec_be = Buffer.from([0x64, 0x63, 0x62, 0x61]); // 1684234849 in BE
  const ts_usec_be = Buffer.from([0x04, 0x03, 0x02, 0x01]); // 67305985 in BE
  const incl_len_be = Buffer.from([0x00, 0x00, 0x00, 0x04]); // 4 in BE
  const orig_len_be = Buffer.from([0x00, 0x00, 0x00, 0x08]); // 8 in BE
  const packet_data_be = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  const sampleRecordBE = Buffer.concat([
    ts_sec_be,
    ts_usec_be,
    incl_len_be,
    orig_len_be,
    packet_data_be,
  ]);

  test('should parse a valid little-endian packet record', () => {
    const result = parsePcapPacketRecord(sampleRecordLE, false);
    expect(result.header.ts_sec).toBe(0x64636261);
    expect(result.header.ts_usec).toBe(0x04030201);
    expect(result.header.incl_len).toBe(4);
    expect(result.header.orig_len).toBe(8);
    expect(result.data).toEqual(packet_data_le);
  });

  test('should parse a valid big-endian packet record', () => {
    const result = parsePcapPacketRecord(sampleRecordBE, true);
    expect(result.header.ts_sec).toBe(0x64636261);
    expect(result.header.ts_usec).toBe(0x04030201);
    expect(result.header.incl_len).toBe(4);
    expect(result.header.orig_len).toBe(8);
    expect(result.data).toEqual(packet_data_be);
  });

  test('should handle truncated packets (incl_len < orig_len)', () => {
    const incl_len_truncated_le = Buffer.from([0x02, 0x00, 0x00, 0x00]); // incl_len = 2
    const orig_len_truncated_le = Buffer.from([0x08, 0x00, 0x00, 0x00]); // orig_len = 8
    const truncatedData = packet_data_le.subarray(0, 2);
    const truncatedRecordLE = Buffer.concat([
      ts_sec_le,
      ts_usec_le,
      incl_len_truncated_le,
      orig_len_truncated_le,
      truncatedData, // Only 2 bytes of data
    ]);
    const result = parsePcapPacketRecord(truncatedRecordLE, false);
    expect(result.header.incl_len).toBe(2);
    expect(result.header.orig_len).toBe(8);
    expect(result.data).toEqual(truncatedData);
    expect(result.data.length).toBe(2);
  });

  test('should throw PcapParsingError for insufficient buffer to read header', () => {
    const shortBuffer = Buffer.alloc(15); // Header is 16 bytes
    expect(() => parsePcapPacketRecord(shortBuffer, false)).toThrow(PcapParsingError);
    expect(() => parsePcapPacketRecord(shortBuffer, false)).toThrow(
      'Insufficient buffer size to read packet record header at offset 0. Need 16 bytes, got 15.',
    );
  });

  test('should throw PcapParsingError for insufficient buffer to read packet data', () => {
    const incl_len_too_large_le = Buffer.from([0x0a, 0x00, 0x00, 0x00]); // incl_len = 10
    const recordWithInsufficientData = Buffer.concat([
      ts_sec_le,
      ts_usec_le,
      incl_len_too_large_le, // Requesting 10 bytes of data
      orig_len_le,
      packet_data_le, // But only providing 4 bytes
    ]);
    expect(() => parsePcapPacketRecord(recordWithInsufficientData, false)).toThrow(
      PcapParsingError,
    );
    expect(() => parsePcapPacketRecord(recordWithInsufficientData, false)).toThrow(
      'Insufficient buffer size to read packet data at offset 16. Need 10 bytes for data, got 4.',
    );
  });

  test('should parse a packet record with zero included length', () => {
    const zero_incl_len_le = Buffer.from([0x00, 0x00, 0x00, 0x00]); // incl_len = 0
    const recordWithZeroInclLen = Buffer.concat([
      ts_sec_le,
      ts_usec_le,
      zero_incl_len_le,
      orig_len_le,
      // No data
    ]);
    const result = parsePcapPacketRecord(recordWithZeroInclLen, false);
    expect(result.header.incl_len).toBe(0);
    expect(result.header.orig_len).toBe(8);
    expect(result.data.length).toBe(0);
    expect(result.data).toEqual(Buffer.alloc(0));
  });

  test('should parse correctly with an offset', () => {
    const offset = 5;
    const prefix = Buffer.alloc(offset, 0xff); // Some garbage prefix
    const recordWithOffset = Buffer.concat([prefix, sampleRecordLE]);
    const result = parsePcapPacketRecord(recordWithOffset, false, offset);
    expect(result.header.ts_sec).toBe(0x64636261);
    expect(result.header.ts_usec).toBe(0x04030201);
    expect(result.header.incl_len).toBe(4);
    expect(result.header.orig_len).toBe(8);
    expect(result.data).toEqual(packet_data_le);
  });

  test('should throw PcapParsingError if offset causes insufficient header read', () => {
    const offset = sampleRecordLE.length - 10; // Not enough space for header after offset
    expect(() => parsePcapPacketRecord(sampleRecordLE, false, offset)).toThrow(PcapParsingError);
    expect(() => parsePcapPacketRecord(sampleRecordLE, false, offset)).toThrow(
      `Insufficient buffer size to read packet record header at offset ${offset}. Need 16 bytes, got 10.`,
    );
  });

  test('should throw PcapParsingError if offset causes insufficient data read', () => {
    // Header is 16 bytes, data is 4 bytes. Total 20.
    // If offset is 10, header starts at 10, ends at 25.
    // Data starts at 26, needs 4 bytes. Buffer length is 20.
    const smallDataPacket = Buffer.concat([
      ts_sec_le,
      ts_usec_le,
      incl_len_le, // incl_len = 4
      orig_len_le,
      packet_data_le, // data = 4 bytes
    ]); // total 20 bytes
    Buffer.concat([Buffer.alloc(10), smallDataPacket]); // total 30 bytes

    // This will make the data read go out of bounds of the *original* smallDataPacket if not handled correctly
    // The actual data to be read is from bufferWithPrefix[10+16] to bufferWithPrefix[10+16+4-1]
    // which is bufferWithPrefix[26] to bufferWithPrefix[29]. This is within the 30 byte buffer.

    // Let's create a case where the *overall buffer* is too small after offset + header
    const recordHeaderOnly = Buffer.concat([ts_sec_le, ts_usec_le, incl_len_le, orig_len_le]); // 16 bytes
    const bufferTooSmallForData = Buffer.concat([Buffer.alloc(5), recordHeaderOnly]); // Total 21 bytes
    // Header from 5 to 20.
    // Data needs 4 bytes from 21.
    // Buffer ends at 20.

    expect(() => parsePcapPacketRecord(bufferTooSmallForData, false, 5)).toThrow(PcapParsingError);
    expect(() => parsePcapPacketRecord(bufferTooSmallForData, false, 5)).toThrow(
      `Insufficient buffer size to read packet data at offset ${5 + 16}. Need 4 bytes for data, got 0.`,
    );
  });
});
