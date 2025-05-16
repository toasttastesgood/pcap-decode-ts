import { BufferOutOfBoundsError } from '../errors';

/**
 * Formats an IPv4 address from a 4-byte buffer.
 * @param buffer - The buffer containing the IPv4 address (4 bytes).
 * @param offset - The offset in the buffer where the IPv4 address starts. Defaults to `0`.
 * @returns The formatted IPv4 address string (e.g., "192.168.1.1").
 * @throws {BufferOutOfBoundsError} If the buffer is too short to contain an IPv4 address at the given offset.
 */
export function formatIPv4(buffer: Buffer, offset: number = 0): string {
  if (offset < 0 || offset + 4 > buffer.length) {
    // Check offset >=0 and ensure 4 bytes are available
    throw new BufferOutOfBoundsError(
      `Offset ${offset} for 4 bytes is out of bounds for buffer of length ${buffer.length}. Cannot format IPv4 address.`,
    );
  }
  return `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
}

/**
 * Formats an IPv6 address from a 16-byte buffer.
 * @param buffer - The buffer containing the IPv6 address (16 bytes).
 * @param offset - The offset in the buffer where the IPv6 address starts. Defaults to `0`.
 * @returns The formatted IPv6 address string (e.g., "2001:0db8:85a3:0000:0000:8a2e:0370:7334").
 *                 Note: This basic formatter does not implement IPv6 address compression (e.g., "::").
 * @throws {BufferOutOfBoundsError} If the buffer is too short to contain an IPv6 address at the given offset.
 */
export function formatIPv6(buffer: Buffer, offset: number = 0): string {
  if (offset < 0 || offset + 16 > buffer.length) {
    // Check offset >=0 and ensure 16 bytes are available
    throw new BufferOutOfBoundsError(
      `Offset ${offset} for 16 bytes is out of bounds for buffer of length ${buffer.length}. Cannot format IPv6 address.`,
    );
  }
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(buffer.readUInt16BE(offset + i).toString(16));
  }
  // Basic formatting, does not handle compression (e.g. ::)
  return parts.join(':');
}
