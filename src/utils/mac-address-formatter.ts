import { Buffer } from 'buffer';
import { BufferOutOfBoundsError } from '../errors';

/**
 * Formats a 6-byte buffer into a human-readable MAC address string.
 * e.g., "AA:BB:CC:DD:EE:FF"
 * @param buffer - The buffer containing the 6-byte MAC address.
 * @returns The formatted MAC address string.
 * @throws {BufferOutOfBoundsError} If the buffer is not 6 bytes long.
 */
export function formatMacAddress(buffer: Buffer): string {
  if (buffer.length !== 6) {
    throw new BufferOutOfBoundsError('MAC address buffer must be 6 bytes long.');
  }
  return Array.from(buffer)
    .map((byte) => byte.toString(16).padStart(2, '0').toLowerCase())
    .join(':');
}
