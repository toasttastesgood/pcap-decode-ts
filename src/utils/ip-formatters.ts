/**
 * Formats an IPv4 address from a 4-byte buffer.
 * @param buffer The buffer containing the IPv4 address (4 bytes).
 * @param offset The offset in the buffer where the IPv4 address starts.
 * @returns The formatted IPv4 address string (e.g., "192.168.1.1").
 * @throws Error if the buffer is too short.
 */
export function formatIPv4(buffer: Buffer, offset: number = 0): string {
  if (offset + 3 >= buffer.length) {
    throw new Error("Buffer too short to contain an IPv4 address.");
  }
  return `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
}

/**
 * Formats an IPv6 address from a 16-byte buffer.
 * @param buffer The buffer containing the IPv6 address (16 bytes).
 * @param offset The offset in the buffer where the IPv6 address starts.
 * @returns The formatted IPv6 address string (e.g., "2001:0db8:85a3:0000:0000:8a2e:0370:7334").
 * @throws Error if the buffer is too short.
 */
export function formatIPv6(buffer: Buffer, offset: number = 0): string {
  if (offset + 15 >= buffer.length) {
    throw new Error("Buffer too short to contain an IPv6 address.");
  }
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(buffer.readUInt16BE(offset + i).toString(16));
  }
  // Basic formatting, does not handle compression (e.g. ::)
  return parts.join(':');
}