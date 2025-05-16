// src/test/pcapng/generic-block-parser.test.ts

import { Buffer } from 'buffer';
import { describe, test, expect } from 'vitest';
import { parsePcapNgGenericBlock, MIN_PCAPNG_BLOCK_SIZE } from '../../pcapng/generic-block-parser';
import { PcapNgBlockType } from '../../pcapng/block-structures';
import { BufferOutOfBoundsError, PcapParsingError } from '../../errors';

describe('parsePcapNgGenericBlock', () => {
  // Helper to create a simple block buffer
  const createBlockBuffer = (
    type: number,
    totalLength: number,
    bodyContent: number[], // array of byte values for the body
    isLittleEndian: boolean,
    overrideTrailingLength?: number, // For testing mismatch
  ): Buffer => {
    if (totalLength < MIN_PCAPNG_BLOCK_SIZE) {
      // Allow creating buffers that are too small for testing error conditions
      // but ensure bodyContent fits if totalLength is somewhat valid.
      if (totalLength >= 8) {
        // Type + Initial Length
        const bodyPlusTrailingLength = totalLength - 8;
        if (bodyContent.length > bodyPlusTrailingLength - (bodyPlusTrailingLength >= 4 ? 4 : 0)) {
          throw new Error('Body content too large for specified totalLength and header/trailer');
        }
      }
    } else {
      const expectedBodyLength = totalLength - 12; // 4 (type) + 4 (len) + 4 (trailing len)
      if (bodyContent.length !== expectedBodyLength) {
        // console.warn(`Warning: bodyContent length ${bodyContent.length} does not match expected body length ${expectedBodyLength} for totalLength ${totalLength}`);
      }
    }

    const buffer = Buffer.alloc(totalLength > 0 ? totalLength : 0); // Handle totalLength = 0 case for error testing
    let offset = 0;

    if (totalLength >= 4) {
      if (isLittleEndian) {
        buffer.writeUInt32LE(type, offset);
      } else {
        buffer.writeUInt32BE(type, offset);
      }
      offset += 4;
    }

    if (totalLength >= 8) {
      if (isLittleEndian) {
        buffer.writeUInt32LE(totalLength, offset);
      } else {
        buffer.writeUInt32BE(totalLength, offset);
      }
      offset += 4;
    }

    // Write body
    for (const byte of bodyContent) {
      if (
        offset <
        totalLength - (overrideTrailingLength !== undefined || totalLength >= 4 ? 4 : 0)
      ) {
        // ensure space for trailing length
        buffer.writeUInt8(byte, offset);
        offset++;
      } else {
        // This can happen if totalLength is too small for bodyContent
        break;
      }
    }

    // Fill remaining body with padding if bodyContent was shorter than expectedBodyLength
    // The block_total_length implies the body includes padding.
    const bodyEndOffset = totalLength - (totalLength >= 4 ? 4 : 0); // Where the body should end before trailing length
    while (offset < bodyEndOffset) {
      buffer.writeUInt8(0, offset); // Padding byte
      offset++;
    }

    if (totalLength >= 4 && offset === totalLength - 4) {
      // Ensure we are at the position for trailing length
      const trailingLength =
        overrideTrailingLength !== undefined ? overrideTrailingLength : totalLength;
      if (isLittleEndian) {
        buffer.writeUInt32LE(trailingLength, offset);
      } else {
        buffer.writeUInt32BE(trailingLength, offset);
      }
      // offset += 4; // No need, we are at the end
    }
    return buffer;
  };

  // --- Valid Blocks ---
  test('should parse a valid minimal block (little-endian)', () => {
    const blockType = PcapNgBlockType.InterfaceDescription;
    const totalLength = MIN_PCAPNG_BLOCK_SIZE; // 12 bytes, empty body
    const body: number[] = [];
    const buffer = createBlockBuffer(blockType, totalLength, body, true);
    const result = parsePcapNgGenericBlock(buffer, 0, true);

    expect(result.header.block_type).toBe(blockType);
    expect(result.header.block_total_length).toBe(totalLength);
    expect(result.body.length).toBe(0); // totalLength (12) - header (8) - trailing length (4) = 0
    expect(result.bytesRead).toBe(totalLength);
  });

  test('should parse a valid minimal block (big-endian)', () => {
    const blockType = PcapNgBlockType.EnhancedPacket;
    const totalLength = MIN_PCAPNG_BLOCK_SIZE; // 12 bytes
    const body: number[] = [];
    const buffer = createBlockBuffer(blockType, totalLength, body, false);
    const result = parsePcapNgGenericBlock(buffer, 0, false);

    expect(result.header.block_type).toBe(blockType);
    expect(result.header.block_total_length).toBe(totalLength);
    expect(result.body.length).toBe(0);
    expect(result.bytesRead).toBe(totalLength);
  });

  test('should parse a valid block with body (little-endian)', () => {
    const blockType = PcapNgBlockType.SectionHeader;
    const bodyContent = [0x01, 0x02, 0x03, 0x04]; // 4 bytes body
    const totalLength = MIN_PCAPNG_BLOCK_SIZE + bodyContent.length; // 12 + 4 = 16
    const buffer = createBlockBuffer(blockType, totalLength, bodyContent, true);
    const result = parsePcapNgGenericBlock(buffer, 0, true);

    expect(result.header.block_type).toBe(blockType);
    expect(result.header.block_total_length).toBe(totalLength);
    expect(result.body.length).toBe(bodyContent.length);
    expect(result.body.equals(Buffer.from(bodyContent))).toBe(true);
    expect(result.bytesRead).toBe(totalLength);
  });

  test('should parse a valid block with body (big-endian)', () => {
    const blockType = PcapNgBlockType.SimplePacket;
    const bodyContent = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]; // 6 bytes body
    // Body needs padding to 32-bit boundary. 6 bytes -> padded to 8 bytes.
    // Total length = 12 (header/trailer) + 8 (padded body) = 20
    const paddedBodyLength = 8;
    const totalLength = MIN_PCAPNG_BLOCK_SIZE + paddedBodyLength; // 12 + 8 = 20
    const buffer = createBlockBuffer(blockType, totalLength, bodyContent, false); // createBlockBuffer handles padding

    const result = parsePcapNgGenericBlock(buffer, 0, false);

    expect(result.header.block_type).toBe(blockType);
    expect(result.header.block_total_length).toBe(totalLength);
    expect(result.body.length).toBe(paddedBodyLength); // Body includes padding

    const expectedBody = Buffer.alloc(paddedBodyLength, 0);
    Buffer.from(bodyContent).copy(expectedBody);
    expect(result.body.equals(expectedBody)).toBe(true);
    expect(result.bytesRead).toBe(totalLength);
  });

  test('should handle padding correctly (body length not multiple of 4)', () => {
    const blockType = PcapNgBlockType.InterfaceStatistics;
    const bodyContent = [0x01, 0x02]; // 2 bytes body
    // Padded to 4 bytes. Total length = 12 + 4 = 16
    const paddedBodyLength = 4;
    const totalLength = MIN_PCAPNG_BLOCK_SIZE + paddedBodyLength;
    const buffer = createBlockBuffer(blockType, totalLength, bodyContent, true);
    const result = parsePcapNgGenericBlock(buffer, 0, true);

    expect(result.header.block_total_length).toBe(totalLength);
    expect(result.body.length).toBe(paddedBodyLength);
    expect(result.body[0]).toBe(0x01);
    expect(result.body[1]).toBe(0x02);
    expect(result.body[2]).toBe(0x00); // Padding
    expect(result.body[3]).toBe(0x00); // Padding
    expect(result.bytesRead).toBe(totalLength);
  });

  test('should parse block with offset in buffer', () => {
    const offset = 10;
    const blockType = PcapNgBlockType.NameResolution;
    const bodyContent = [0xde, 0xad, 0xbe, 0xef];
    const totalLength = MIN_PCAPNG_BLOCK_SIZE + bodyContent.length; // 16
    const blockBuffer = createBlockBuffer(blockType, totalLength, bodyContent, false);

    const fullBuffer = Buffer.concat([Buffer.alloc(offset), blockBuffer]);
    const result = parsePcapNgGenericBlock(fullBuffer, offset, false);

    expect(result.header.block_type).toBe(blockType);
    expect(result.header.block_total_length).toBe(totalLength);
    expect(result.body.equals(Buffer.from(bodyContent))).toBe(true);
    expect(result.bytesRead).toBe(totalLength);
  });

  // --- Error Handling ---
  test('should throw BufferOutOfBoundsError if buffer is too small for generic header', () => {
    const buffer = Buffer.alloc(7); // Needs 8 for header
    expect(() => parsePcapNgGenericBlock(buffer, 0, true)).toThrow(BufferOutOfBoundsError);
    expect(() => parsePcapNgGenericBlock(buffer, 0, true)).toThrow(
      'Insufficient data for generic block header at offset 0. Need 8 bytes, got 7.',
    );
  });

  test('should throw BufferOutOfBoundsError if buffer is too small for generic header with offset', () => {
    const buffer = Buffer.alloc(10); // total
    const offset = 5; // effective length 5
    expect(() => parsePcapNgGenericBlock(buffer, offset, true)).toThrow(BufferOutOfBoundsError);
    expect(() => parsePcapNgGenericBlock(buffer, offset, true)).toThrow(
      `Insufficient data for generic block header at offset ${offset}. Need 8 bytes, got 5.`,
    );
  });

  test('should throw PcapParsingError if block_total_length is less than minimum size', () => {
    const invalidTotalLength = MIN_PCAPNG_BLOCK_SIZE - 1; // e.g., 11
    createBlockBuffer(PcapNgBlockType.CustomDoNotCopy, invalidTotalLength, [], true);
    // The createBlockBuffer might not fully form it if length is too small,
    // but it should write the initial length field.
    // Manually ensure the length field is written for the test:
    const minimalHeaderBuffer = Buffer.alloc(8);
    minimalHeaderBuffer.writeUInt32LE(PcapNgBlockType.CustomDoNotCopy, 0);
    minimalHeaderBuffer.writeUInt32LE(invalidTotalLength, 4);

    expect(() => parsePcapNgGenericBlock(minimalHeaderBuffer, 0, true)).toThrow(PcapParsingError);
    expect(() => parsePcapNgGenericBlock(minimalHeaderBuffer, 0, true)).toThrow(
      `Invalid block_total_length at offset 4: ${invalidTotalLength}. Minimum is ${MIN_PCAPNG_BLOCK_SIZE}.`,
    );
  });

  test('should throw PcapParsingError if block_total_length is 8 (no space for trailing length)', () => {
    const invalidTotalLength = 8;
    const buffer = Buffer.alloc(8);
    buffer.writeUInt32LE(PcapNgBlockType.InterfaceDescription, 0);
    buffer.writeUInt32LE(invalidTotalLength, 4);
    expect(() => parsePcapNgGenericBlock(buffer, 0, true)).toThrow(PcapParsingError);
    expect(() => parsePcapNgGenericBlock(buffer, 0, true)).toThrow(
      `Invalid block_total_length at offset 4: ${invalidTotalLength}. Minimum is ${MIN_PCAPNG_BLOCK_SIZE}.`,
    );
  });

  test('should throw BufferOutOfBoundsError if buffer is too small for declared block_total_length', () => {
    const declaredTotalLength = 20;
    // Buffer is only 16 bytes, but header declares 20
    const buffer = createBlockBuffer(
      PcapNgBlockType.EnhancedPacket,
      declaredTotalLength,
      [1, 2, 3, 4],
      true,
    ); // body is 4 bytes, total 16
    buffer.subarray(0, 16); // Simulate truncated buffer

    // Manually write the header for this specific test case
    const testBuffer = Buffer.alloc(16);
    testBuffer.writeUInt32LE(PcapNgBlockType.EnhancedPacket, 0); // type
    testBuffer.writeUInt32LE(declaredTotalLength, 4); // declared length (20)
    // ... rest of buffer is shorter than declaredTotalLength

    expect(() => parsePcapNgGenericBlock(testBuffer, 0, true)).toThrow(BufferOutOfBoundsError);
    expect(() => parsePcapNgGenericBlock(testBuffer, 0, true)).toThrow(
      `Insufficient data for full block at offset 0. Declared length ${declaredTotalLength}, available ${testBuffer.length}.`,
    );
  });

  test('should throw PcapParsingError if leading and trailing block_total_length mismatch', () => {
    const blockType = PcapNgBlockType.SectionHeader;
    const totalLength = 16; // body of 4
    const bodyContent = [1, 2, 3, 4];
    const mismatchedTrailingLength = 12;
    const buffer = createBlockBuffer(
      blockType,
      totalLength,
      bodyContent,
      false,
      mismatchedTrailingLength,
    );

    expect(() => parsePcapNgGenericBlock(buffer, 0, false)).toThrow(PcapParsingError);
    expect(() => parsePcapNgGenericBlock(buffer, 0, false)).toThrow(
      `Mismatch between leading block_total_length (${totalLength}) at offset 4 and trailing block_total_length (${mismatchedTrailingLength}) at offset ${totalLength - 4}.`,
    );
  });

  test('should correctly parse a block with body length that needs no padding', () => {
    const blockType = PcapNgBlockType.InterfaceDescription;
    const bodyContent = [1, 2, 3, 4, 5, 6, 7, 8]; // 8 bytes, multiple of 4
    const totalLength = MIN_PCAPNG_BLOCK_SIZE + bodyContent.length; // 12 + 8 = 20
    const buffer = createBlockBuffer(blockType, totalLength, bodyContent, true);
    const result = parsePcapNgGenericBlock(buffer, 0, true);

    expect(result.header.block_type).toBe(blockType);
    expect(result.header.block_total_length).toBe(totalLength);
    expect(result.body.length).toBe(bodyContent.length);
    expect(result.body.equals(Buffer.from(bodyContent))).toBe(true);
    expect(result.bytesRead).toBe(totalLength);
  });
});
