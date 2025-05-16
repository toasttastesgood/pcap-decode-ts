import { BufferOutOfBoundsError } from '../errors';

/**
 * Reads a signed 8-bit integer from the buffer at the specified offset.
 * @param buffer The buffer to read from.
 * @param offset The offset to start reading from.
 * @returns The signed 8-bit integer.
 * @throws BufferOutOfBoundsError if the read operation goes beyond buffer bounds.
 */
export function readInt8(buffer: Buffer, offset: number): number {
  if (offset < 0 || offset >= buffer.length) {
    throw new BufferOutOfBoundsError(
      `Offset ${offset} is out of bounds for buffer of length ${buffer.length}`,
    );
  }
  return buffer.readInt8(offset);
}

/**
 * Reads an unsigned 8-bit integer from the buffer at the specified offset.
 * @param buffer The buffer to read from.
 * @param offset The offset to start reading from.
 * @returns The unsigned 8-bit integer.
 * @throws BufferOutOfBoundsError if the read operation goes beyond buffer bounds.
 */
export function readUint8(buffer: Buffer, offset: number): number {
  if (offset < 0 || offset >= buffer.length) {
    throw new BufferOutOfBoundsError(
      `Offset ${offset} is out of bounds for buffer of length ${buffer.length}`,
    );
  }
  return buffer.readUInt8(offset);
}

/**
 * Reads a signed 16-bit integer in big-endian format from the buffer at the specified offset.
 * @param buffer The buffer to read from.
 * @param offset The offset to start reading from.
 * @returns The signed 16-bit integer.
 * @throws BufferOutOfBoundsError if the read operation goes beyond buffer bounds.
 */
export function readInt16BE(buffer: Buffer, offset: number): number {
  if (offset < 0 || offset + 1 >= buffer.length) {
    throw new BufferOutOfBoundsError(
      `Offset ${offset} for 2 bytes is out of bounds for buffer of length ${buffer.length}`,
    );
  }
  return buffer.readInt16BE(offset);
}

/**
 * Reads a signed 16-bit integer in little-endian format from the buffer at the specified offset.
 * @param buffer The buffer to read from.
 * @param offset The offset to start reading from.
 * @returns The signed 16-bit integer.
 * @throws BufferOutOfBoundsError if the read operation goes beyond buffer bounds.
 */
export function readInt16LE(buffer: Buffer, offset: number): number {
  if (offset < 0 || offset + 1 >= buffer.length) {
    throw new BufferOutOfBoundsError(
      `Offset ${offset} for 2 bytes is out of bounds for buffer of length ${buffer.length}`,
    );
  }
  return buffer.readInt16LE(offset);
}

/**
 * Reads an unsigned 16-bit integer in big-endian format from the buffer at the specified offset.
 * @param buffer The buffer to read from.
 * @param offset The offset to start reading from.
 * @returns The unsigned 16-bit integer.
 * @throws BufferOutOfBoundsError if the read operation goes beyond buffer bounds.
 */
export function readUint16BE(buffer: Buffer, offset: number): number {
  if (offset < 0 || offset + 1 >= buffer.length) {
    throw new BufferOutOfBoundsError(
      `Offset ${offset} for 2 bytes is out of bounds for buffer of length ${buffer.length}`,
    );
  }
  return buffer.readUInt16BE(offset);
}

/**
 * Reads an unsigned 16-bit integer in little-endian format from the buffer at the specified offset.
 * @param buffer The buffer to read from.
 * @param offset The offset to start reading from.
 * @returns The unsigned 16-bit integer.
 * @throws BufferOutOfBoundsError if the read operation goes beyond buffer bounds.
 */
export function readUint16LE(buffer: Buffer, offset: number): number {
  if (offset < 0 || offset + 1 >= buffer.length) {
    throw new BufferOutOfBoundsError(
      `Offset ${offset} for 2 bytes is out of bounds for buffer of length ${buffer.length}`,
    );
  }
  return buffer.readUInt16LE(offset);
}

/**
 * Reads a signed 32-bit integer in big-endian format from the buffer at the specified offset.
 * @param buffer The buffer to read from.
 * @param offset The offset to start reading from.
 * @returns The signed 32-bit integer.
 * @throws BufferOutOfBoundsError if the read operation goes beyond buffer bounds.
 */
export function readInt32BE(buffer: Buffer, offset: number): number {
  if (offset < 0 || offset + 3 >= buffer.length) {
    throw new BufferOutOfBoundsError(
      `Offset ${offset} for 4 bytes is out of bounds for buffer of length ${buffer.length}`,
    );
  }
  return buffer.readInt32BE(offset);
}

/**
 * Reads a signed 32-bit integer in little-endian format from the buffer at the specified offset.
 * @param buffer The buffer to read from.
 * @param offset The offset to start reading from.
 * @returns The signed 32-bit integer.
 * @throws BufferOutOfBoundsError if the read operation goes beyond buffer bounds.
 */
export function readInt32LE(buffer: Buffer, offset: number): number {
  if (offset < 0 || offset + 3 >= buffer.length) {
    throw new BufferOutOfBoundsError(
      `Offset ${offset} for 4 bytes is out of bounds for buffer of length ${buffer.length}`,
    );
  }
  return buffer.readInt32LE(offset);
}

/**
 * Reads an unsigned 32-bit integer in big-endian format from the buffer at the specified offset.
 * @param buffer The buffer to read from.
 * @param offset The offset to start reading from.
 * @returns The unsigned 32-bit integer.
 * @throws BufferOutOfBoundsError if the read operation goes beyond buffer bounds.
 */
export function readUint32BE(buffer: Buffer, offset: number): number {
  if (offset < 0 || offset + 3 >= buffer.length) {
    throw new BufferOutOfBoundsError(
      `Offset ${offset} for 4 bytes is out of bounds for buffer of length ${buffer.length}`,
    );
  }
  return buffer.readUInt32BE(offset);
}

/**
 * Reads an unsigned 32-bit integer in little-endian format from the buffer at the specified offset.
 * @param buffer The buffer to read from.
 * @param offset The offset to start reading from.
 * @returns The unsigned 32-bit integer.
 * @throws BufferOutOfBoundsError if the read operation goes beyond buffer bounds.
 */
export function readUint32LE(buffer: Buffer, offset: number): number {
  if (offset < 0 || offset + 3 >= buffer.length) {
    throw new BufferOutOfBoundsError(
      `Offset ${offset} for 4 bytes is out of bounds for buffer of length ${buffer.length}`,
    );
  }
  return buffer.readUInt32LE(offset);
}

/**
 * Reads a signed 64-bit integer (BigInt) in big-endian format from the buffer at the specified offset.
 * @param buffer The buffer to read from.
 * @param offset The offset to start reading from.
 * @returns The signed 64-bit integer as a BigInt.
 * @throws BufferOutOfBoundsError if the read operation goes beyond buffer bounds.
 */
export function readBigInt64BE(buffer: Buffer, offset: number): bigint {
  if (offset < 0 || offset + 7 >= buffer.length) {
    throw new BufferOutOfBoundsError(
      `Offset ${offset} for 8 bytes is out of bounds for buffer of length ${buffer.length}`,
    );
  }
  return buffer.readBigInt64BE(offset);
}

/**
 * Reads a signed 64-bit integer (BigInt) in little-endian format from the buffer at the specified offset.
 * @param buffer The buffer to read from.
 * @param offset The offset to start reading from.
 * @returns The signed 64-bit integer as a BigInt.
 * @throws BufferOutOfBoundsError if the read operation goes beyond buffer bounds.
 */
export function readBigInt64LE(buffer: Buffer, offset: number): bigint {
  if (offset < 0 || offset + 7 >= buffer.length) {
    throw new BufferOutOfBoundsError(
      `Offset ${offset} for 8 bytes is out of bounds for buffer of length ${buffer.length}`,
    );
  }
  return buffer.readBigInt64LE(offset);
}

/**
 * Reads an unsigned 64-bit integer (BigInt) in big-endian format from the buffer at the specified offset.
 * @param buffer The buffer to read from.
 * @param offset The offset to start reading from.
 * @returns The unsigned 64-bit integer as a BigInt.
 * @throws BufferOutOfBoundsError if the read operation goes beyond buffer bounds.
 */
export function readBigUint64BE(buffer: Buffer, offset: number): bigint {
  if (offset < 0 || offset + 7 >= buffer.length) {
    throw new BufferOutOfBoundsError(
      `Offset ${offset} for 8 bytes is out of bounds for buffer of length ${buffer.length}`,
    );
  }
  return buffer.readBigUInt64BE(offset);
}

/**
 * Reads an unsigned 64-bit integer (BigInt) in little-endian format from the buffer at the specified offset.
 * @param buffer The buffer to read from.
 * @param offset The offset to start reading from.
 * @returns The unsigned 64-bit integer as a BigInt.
 * @throws BufferOutOfBoundsError if the read operation goes beyond buffer bounds.
 */
export function readBigUint64LE(buffer: Buffer, offset: number): bigint {
  if (offset < 0 || offset + 7 >= buffer.length) {
    throw new BufferOutOfBoundsError(
      `Offset ${offset} for 8 bytes is out of bounds for buffer of length ${buffer.length}`,
    );
  }
  return buffer.readBigUInt64LE(offset);
}
