// src/pcapng/generic-block-parser.ts

import { Buffer } from 'buffer';
import { PcapNgGenericBlockHeader } from './block-structures';
import { BufferOutOfBoundsError, PcapParsingError } from '../errors';
import { readUint32BE, readUint32LE } from '../utils/byte-readers';

/**
 * Represents the result of parsing a generic PCAPng block.
 */
export interface ParsedPcapNgGenericBlock {
  header: PcapNgGenericBlockHeader;
  body: Buffer; // Raw block body, including any padding, between the header and the trailing block_total_length
  bytesRead: number; // Total bytes consumed by this block, including the trailing block_total_length
}

/**
 * Minimum size of a PCAPng block (Block Type + Block Total Length + Block Total Length).
 * Block Type (4 bytes) + Block Total Length (4 bytes) = 8 bytes for the header.
 * The body can be empty.
 * Trailing Block Total Length (4 bytes).
 * So, minimum is 4 + 4 + 0 (empty body) + 4 = 12 bytes.
 * However, the `block_total_length` field itself must be at least 12.
 * If `block_total_length` is 8, it means only type and length, which is invalid as it's missing the trailing length.
 * The problem states "block_total_length includes the 8 bytes of the generic header itself".
 * And "Handle padding at the end of the block body to ensure the next block starts at a 32-bit boundary.
 * The total length read must match block_total_length."
 * This implies block_total_length is the *entire* size of the block on disk/in stream.
 * A block consists of:
 *   - Block Type (4 bytes)
 *   - Block Total Length (4 bytes)  <-- This is header.block_total_length
 *   - Block Body (N bytes)
 *   - Block Total Length (4 bytes)  <-- Repeated
 * The value of `header.block_total_length` is the length from the start of Block Type
 * to the end of the *repeated* Block Total Length.
 * So, `header.block_total_length` must be at least 12 (4 + 4 + 0 for body + 4).
 */
export const MIN_PCAPNG_BLOCK_SIZE = 12; // Type(4) + Length(4) + Body(0 min) + Length(4)

/**
 * Parses a generic PCAPng block from a buffer.
 *
 * PCAPng blocks have the following generic structure:
 *   - Block Type (4 bytes)
 *   - Block Total Length (4 bytes)
 *   - Block Body (variable, padded to 32-bit boundary)
 *   - Block Total Length (4 bytes, repetition of the previous one)
 *
 * The `block_total_length` field in the header is the total length of the block,
 * including the type, both length fields, and the body.
 *
 * @param buffer The buffer containing the PCAPng block data.
 * @param offset The offset in the buffer where the block starts.
 * @param isLittleEndian Boolean indicating if the data is in little-endian format.
 * @returns An object containing the parsed generic header, the raw block body, and total bytes read.
 * @throws {BufferOutOfBoundsError} If the buffer does not contain enough data for the header or the full block.
 * @throws {PcapParsingError} If the block_total_length is invalid (e.g., less than minimum size).
 */
export function parsePcapNgGenericBlock(
  buffer: Buffer,
  offset: number,
  isLittleEndian: boolean,
): ParsedPcapNgGenericBlock {
  // Minimum data needed for the generic header (block_type + block_total_length)
  const GENERIC_HEADER_SIZE = 8;
  if (buffer.length < offset + GENERIC_HEADER_SIZE) {
    throw new BufferOutOfBoundsError(
      `Insufficient data for generic block header at offset ${offset}. Need ${GENERIC_HEADER_SIZE} bytes, got ${buffer.length - offset}.`,
    );
  }

  const block_type = isLittleEndian ? readUint32LE(buffer, offset) : readUint32BE(buffer, offset);
  const block_total_length = isLittleEndian
    ? readUint32LE(buffer, offset + 4)
    : readUint32BE(buffer, offset + 4);

  if (block_total_length < MIN_PCAPNG_BLOCK_SIZE) {
    throw new PcapParsingError(
      `Invalid block_total_length at offset ${offset + 4}: ${block_total_length}. Minimum is ${MIN_PCAPNG_BLOCK_SIZE}.`,
    );
  }

  if (buffer.length < offset + block_total_length) {
    throw new BufferOutOfBoundsError(
      `Insufficient data for full block at offset ${offset}. Declared length ${block_total_length}, available ${buffer.length - offset}.`,
    );
  }

  // The block body is located after the generic header (8 bytes) and
  // before the trailing block_total_length (4 bytes).
  // Body length = block_total_length - Generic Header Size (8) - Trailing Length Field (4)
  const bodyLength = block_total_length - GENERIC_HEADER_SIZE - 4;
  if (bodyLength < 0) {
    // This case should be caught by block_total_length < MIN_PCAPNG_BLOCK_SIZE, but as a safeguard:
    throw new PcapParsingError(
      `Calculated negative body length (${bodyLength}) for block_total_length ${block_total_length} at offset ${offset + 4}.`,
    );
  }

  const blockBody = buffer.subarray(
    offset + GENERIC_HEADER_SIZE,
    offset + GENERIC_HEADER_SIZE + bodyLength,
  );

  // Verify the trailing block_total_length
  const trailing_block_total_length_offset = offset + block_total_length - 4;
  const trailing_block_total_length = isLittleEndian
    ? readUint32LE(buffer, trailing_block_total_length_offset)
    : readUint32BE(buffer, trailing_block_total_length_offset);

  if (trailing_block_total_length !== block_total_length) {
    throw new PcapParsingError(
      `Mismatch between leading block_total_length (${block_total_length}) at offset ${offset + 4} and trailing block_total_length (${trailing_block_total_length}) at offset ${trailing_block_total_length_offset}.`,
    );
  }

  // Padding: The block_total_length already accounts for padding, as the entire block
  // must be a multiple of 4 bytes. The body extracted (block_total_length - 12)
  // will contain any necessary padding at its end.

  return {
    header: {
      block_type,
      block_total_length,
    },
    body: blockBody,
    bytesRead: block_total_length, // The total length consumed from the buffer
  };
}
