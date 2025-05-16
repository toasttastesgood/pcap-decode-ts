import {
  PcapNgSectionHeaderBlock,
  PcapNgInterfaceDescriptionBlock,
  PcapNgEnhancedPacketBlock,
  PcapNgNameResolutionBlock,
  PcapNgOption,
  PcapNgNameResolutionRecord, // Generic record, specific parsing is done in the NRB parser
} from './block-structures';
import {
  readUint16BE,
  readUint16LE,
  readUint32BE,
  readUint32LE,
  readBigUint64BE,
  readBigUint64LE,
} from '../utils/byte-readers';
import { PcapParsingError } from '../errors';

// Helper functions to read numbers based on endianness
function readUint16(buffer: Buffer, offset: number, isBigEndian: boolean): number {
  return isBigEndian ? readUint16BE(buffer, offset) : readUint16LE(buffer, offset);
}

function readUint32(buffer: Buffer, offset: number, isBigEndian: boolean): number {
  return isBigEndian ? readUint32BE(buffer, offset) : readUint32LE(buffer, offset);
}

function readBigUint64(buffer: Buffer, offset: number, isBigEndian: boolean): bigint {
  return isBigEndian ? readBigUint64BE(buffer, offset) : readBigUint64LE(buffer, offset);
}

/**
 * Parses the options from a block body.
 * @param buffer - The buffer containing the options.
 * @param isBigEndian - Whether the data is in big-endian format.
 * @returns An array of {@link PcapNgOption} objects.
 * @throws {PcapParsingError} If an option's declared length exceeds buffer bounds.
 */
export function parseOptions(buffer: Buffer, isBigEndian: boolean): PcapNgOption[] {
  const options: PcapNgOption[] = [];
  let offset = 0;

  while (offset < buffer.length) {
    const optionCode = readUint16(buffer, offset, isBigEndian);
    offset += 2;
    const optionLength = readUint16(buffer, offset, isBigEndian);
    offset += 2;

    if (optionCode === 0) {
      // opt_endofopt
      break;
    }

    if (offset + optionLength > buffer.length) {
      throw new PcapParsingError(
        `Option length ${optionLength} at offset ${offset - 2} exceeds buffer bounds (buffer length ${buffer.length}).`,
      );
    }

    const optionValue = Buffer.from(buffer.subarray(offset, offset + optionLength));
    options.push({ code: optionCode, length: optionLength, value: optionValue });
    offset += optionLength;

    // Options are padded to a 32-bit boundary
    const padding = (4 - (optionLength % 4)) % 4;
    offset += padding;
  }
  return options;
}

/**
 * Parses a Section Header Block (SHB).
 * @param blockBody - The raw block body buffer, excluding the generic block header.
 * @param isBigEndian - Indicates the byte order of the block body, determined from the SHB's magic number.
 * @returns A parsed {@link PcapNgSectionHeaderBlock} object. The `block_type` field is set to the known SHB type (0x0A0D0D0A), and `block_total_length` is a placeholder (0), as these are typically part of the generic block header processed by the caller.
 */
export function parseSectionHeaderBlock(
  blockBody: Buffer,
  isBigEndian: boolean,
): PcapNgSectionHeaderBlock {
  let offset = 0;

  // Byte Order Magic (4 bytes) - This is used by the generic parser to determine endianness for this section.
  // The `isBigEndian` parameter for this function is determined from this magic number by the caller.
  const byteOrderMagic = readUint32(blockBody, offset, isBigEndian);
  offset += 4;

  // Major Version (2 bytes)
  const majorVersion = readUint16(blockBody, offset, isBigEndian);
  offset += 2;

  // Minor Version (2 bytes)
  const minorVersion = readUint16(blockBody, offset, isBigEndian);
  offset += 2;

  // Section Length (8 bytes)
  const sectionLength = readBigUint64(blockBody, offset, isBigEndian);
  offset += 8;

  // Options (variable length)
  const optionsBuffer = blockBody.subarray(offset);
  const options = parseOptions(optionsBuffer, isBigEndian);

  return {
    // block_type and block_total_length are part of the generic block structure,
    // handled by the generic parser, not part of the specific blockBody passed here.
    // However, to satisfy the interface, we might need to reconsider how these are passed or set.
    // For now, assuming they are not part of this specific parser's direct output from blockBody.
    // This might require adjustment based on how PcapNgGenericBlockHeader is integrated.
    // For the purpose of this function, we are parsing the *body* of the SHB.
    // The caller (generic block parser) would have block_type and block_total_length.
    // Let's assume the interface expects these to be filled, even if redundantly for now.
    // This is a common pattern if the specific parser returns the complete block structure.
    // If the design is that this parser *only* returns SHB-specific fields, the interface would be different.
    // Given PcapNgSectionHeaderBlock extends PcapNgGenericBlockHeader, it needs these fields.
    // We'll add dummy values for now, as they are not derived from blockBody itself.
    block_type: 0x0a0d0d0a, // SHB type, known
    block_total_length: 0, // This would be the full block length, known by the generic parser
    byte_order_magic: byteOrderMagic,
    major_version: majorVersion,
    minor_version: minorVersion,
    section_length: sectionLength,
    options,
  };
}

/**
 * Parses an Interface Description Block (IDB).
 * @param blockBody - The raw block body buffer, excluding the generic block header.
 * @param isBigEndian - Indicates the byte order of the block body.
 * @returns A parsed {@link PcapNgInterfaceDescriptionBlock} object. The `block_type` field is set to the known IDB type (0x00000001), and `block_total_length` is a placeholder (0), as these are typically part of the generic block header processed by the caller.
 */
export function parseInterfaceDescriptionBlock(
  blockBody: Buffer,
  isBigEndian: boolean,
): PcapNgInterfaceDescriptionBlock {
  let offset = 0;

  // LinkType (2 bytes)
  const linktype = readUint16(blockBody, offset, isBigEndian);
  offset += 2;

  // Reserved (2 bytes)
  const reserved = readUint16(blockBody, offset, isBigEndian);
  offset += 2;

  // SnapLen (4 bytes)
  const snaplen = readUint32(blockBody, offset, isBigEndian);
  offset += 4;

  // Options (variable length)
  const optionsBuffer = blockBody.subarray(offset);
  const options = parseOptions(optionsBuffer, isBigEndian);

  return {
    block_type: 0x00000001, // IDB type, known
    block_total_length: 0, // This would be the full block length, known by the generic parser
    linktype,
    reserved,
    snaplen,
    options,
  };
}

/**
 * Parses an Enhanced Packet Block (EPB).
 * @param blockBody - The raw block body buffer, excluding the generic block header.
 * @param isBigEndian - Indicates the byte order of the block body.
 * @returns A parsed {@link PcapNgEnhancedPacketBlock} object. The `block_type` field is set to the known EPB type (0x00000006), and `block_total_length` is a placeholder (0), as these are typically part of the generic block header processed by the caller.
 * @throws {PcapParsingError} If `captured_len` or option parsing exceeds buffer bounds.
 */
export function parseEnhancedPacketBlock(
  blockBody: Buffer,
  isBigEndian: boolean,
): PcapNgEnhancedPacketBlock {
  let offset = 0;

  // Interface ID (4 bytes)
  const interfaceId = readUint32(blockBody, offset, isBigEndian);
  offset += 4;

  // Timestamp (High) (4 bytes)
  const timestampHigh = readUint32(blockBody, offset, isBigEndian);
  offset += 4;

  // Timestamp (Low) (4 bytes)
  const timestampLow = readUint32(blockBody, offset, isBigEndian);
  offset += 4;

  // Captured Packet Length (4 bytes)
  const capturedLen = readUint32(blockBody, offset, isBigEndian);
  offset += 4;

  // Original Packet Length (4 bytes)
  const originalLen = readUint32(blockBody, offset, isBigEndian);
  offset += 4;

  // Packet Data (variable length, capturedLen bytes)
  if (offset + capturedLen > blockBody.length) {
    throw new PcapParsingError(
      `EPB captured_len (${capturedLen}) at offset ${offset - 4} exceeds block body bounds (blockBody length ${blockBody.length}).`,
    );
  }
  const packetData = Buffer.from(blockBody.subarray(offset, offset + capturedLen));
  offset += capturedLen;

  // Packet Data must be padded to a 32-bit boundary
  const paddingLength = (4 - (capturedLen % 4)) % 4;
  offset += paddingLength;

  // Options (variable length)
  // Ensure options parsing does not read past the end of the blockBody
  if (offset > blockBody.length) {
    // This case should ideally not happen if padding is correct and capturedLen is accurate.
    // If it does, it implies an issue with packet_data padding or prior field lengths.
    throw new PcapParsingError(
      `EPB offset (${offset}) exceeds block body bounds (blockBody length ${blockBody.length}) before parsing options.`,
    );
  }
  const optionsBuffer = blockBody.subarray(offset);
  const options = parseOptions(optionsBuffer, isBigEndian);

  return {
    block_type: 0x00000006, // EPB type, known
    block_total_length: 0, // This would be the full block length, known by the generic parser
    interface_id: interfaceId,
    timestamp_high: timestampHigh,
    timestamp_low: timestampLow,
    captured_len: capturedLen,
    original_len: originalLen,
    packet_data: packetData,
    options,
  };
}

/**
 * Parses a Name Resolution Block (NRB).
 * @param blockBody - The raw block body buffer, excluding the generic block header.
 * @param isBigEndian - Indicates the byte order of the block body.
 * @returns A parsed {@link PcapNgNameResolutionBlock} object. The `block_type` field is set to the known NRB type (0x00000004), and `block_total_length` is a placeholder (0), as these are typically part of the generic block header processed by the caller.
 * @throws {PcapParsingError} If record or option lengths exceed buffer bounds.
 */
export function parseNameResolutionBlock(
  blockBody: Buffer,
  isBigEndian: boolean,
): PcapNgNameResolutionBlock {
  let offset = 0;
  const records: PcapNgNameResolutionRecord[] = [];

  // Parse Records
  while (offset < blockBody.length) {
    // Record Type (2 bytes)
    const recordType = readUint16(blockBody, offset, isBigEndian);
    offset += 2;

    // nrb_record_end: If record_type is 0, it's the end of records.
    if (recordType === 0) {
      break;
    }

    // Record Value Length (2 bytes)
    const recordValueLength = readUint16(blockBody, offset, isBigEndian);
    offset += 2;

    // Record Value (variable length)
    if (offset + recordValueLength > blockBody.length) {
      throw new PcapParsingError(
        `NRB record_value_length (${recordValueLength}) at offset ${offset - 2} for record_type ${recordType} exceeds block body bounds (blockBody length ${blockBody.length}).`,
      );
    }
    const recordValue = Buffer.from(blockBody.subarray(offset, offset + recordValueLength));
    offset += recordValueLength;

    records.push({
      record_type: recordType,
      record_value_length: recordValueLength,
      record_value: recordValue,
    });

    // Records are padded to a 32-bit boundary (Record Type + Record Value Length + Record Value)
    // The total length of these three fields is 2 + 2 + recordValueLength = 4 + recordValueLength
    const recordDataLength = 4 + recordValueLength;
    const padding = (4 - (recordDataLength % 4)) % 4;
    offset += padding;
  }

  // Options (variable length)
  // Ensure options parsing does not read past the end of the blockBody
  if (offset > blockBody.length) {
    throw new PcapParsingError(
      `NRB offset (${offset}) exceeds block body bounds (blockBody length ${blockBody.length}) before parsing options.`,
    );
  }
  const optionsBuffer = blockBody.subarray(offset);
  const options = parseOptions(optionsBuffer, isBigEndian);

  return {
    block_type: 0x00000004, // NRB type, known
    block_total_length: 0, // This would be the full block length, known by the generic parser
    records,
    options,
  };
}
