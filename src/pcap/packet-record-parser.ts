import { PcapPacketRecordHeader } from './packet-record-header';
import { readUint32BE, readUint32LE } from '../utils/byte-readers';
import { PcapParsingError } from '../errors';

/**
 * Represents the result of parsing a PCAP packet record.
 */
export interface ParsedPcapPacketRecord {
  header: PcapPacketRecordHeader;
  data: Buffer;
}

/**
 * Parses a PCAP packet record from the provided buffer.
 *
 * @param buffer The buffer containing the packet record data.
 * @param isBigEndian True if the data is big-endian, false for little-endian.
 * @param offset The offset in the buffer to start reading from. Defaults to 0.
 * @returns An object containing the parsed packet record header and the packet data.
 * @throws PcapParsingError if the buffer is too small or data is malformed.
 */
export function parsePcapPacketRecord(
  buffer: Buffer,
  isBigEndian: boolean,
  offset: number = 0,
): ParsedPcapPacketRecord {
  const headerSize = 16; // ts_sec (4) + ts_usec (4) + incl_len (4) + orig_len (4)

  if (buffer.length < offset + headerSize) {
    throw new PcapParsingError(
      `Insufficient buffer size to read packet record header at offset ${offset}. Need ${headerSize} bytes, got ${
        buffer.length - offset
      }.`,
    );
  }

  const readUint32 = isBigEndian ? readUint32BE : readUint32LE;

  const ts_sec = readUint32(buffer, offset);
  const ts_usec = readUint32(buffer, offset + 4);
  const incl_len = readUint32(buffer, offset + 8);
  const orig_len = readUint32(buffer, offset + 12);

  const header: PcapPacketRecordHeader = {
    ts_sec,
    ts_usec,
    incl_len,
    orig_len,
  };

  if (buffer.length < offset + headerSize + incl_len) {
    throw new PcapParsingError(
      `Insufficient buffer size to read packet data at offset ${offset + headerSize}. Need ${incl_len} bytes for data, got ${
        buffer.length - (offset + headerSize)
      }.`,
    );
  }

  const data = buffer.subarray(offset + headerSize, offset + headerSize + incl_len);

  return { header, data };
}
