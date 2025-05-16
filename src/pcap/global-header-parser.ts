import { PcapGlobalHeader } from './global-header';
import { InvalidFileFormatError, BufferOutOfBoundsError } from '../errors';

/**
 * Parses the PCAP global header from a buffer.
 *
 * @param buffer - The buffer containing the PCAP global header data.
 * @returns The parsed PCAP global header.
 * @throws {InvalidFileFormatError} If the magic number is invalid.
 * @throws {BufferOutOfBoundsError} If the buffer is too small to contain the global header.
 */
export function parsePcapGlobalHeader(buffer: Buffer): PcapGlobalHeader {
  if (buffer.length < 24) {
    throw new BufferOutOfBoundsError(
      'Buffer too small to contain PCAP Global Header. Expected 24 bytes.',
    );
  }

  const dataView = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  const magic_number = dataView.getUint32(0, false); // Read as big-endian first to check

  let littleEndian: boolean;

  if (magic_number === 0xa1b2c3d4) {
    littleEndian = false;
  } else if (magic_number === 0xd4c3b2a1) {
    littleEndian = true;
    // Re-read magic_number if it was actually little-endian, though it will be the same value
    // This is more for clarity and consistency if we were to read it again using the determined endianness.
    // For now, the initial read is sufficient for validation.
  } else {
    throw new InvalidFileFormatError(
      `Invalid magic number: 0x${magic_number.toString(16)}. Expected 0xa1b2c3d4 or 0xd4c3b2a1.`,
    );
  }

  const version_major = dataView.getUint16(4, littleEndian);
  const version_minor = dataView.getUint16(6, littleEndian);
  const thiszone = dataView.getInt32(8, littleEndian);
  const sigfigs = dataView.getUint32(12, littleEndian);
  const snaplen = dataView.getUint32(16, littleEndian);
  const network = dataView.getUint32(20, littleEndian);

  return {
    magic_number,
    version_major,
    version_minor,
    thiszone,
    sigfigs,
    snaplen,
    network,
  };
}
