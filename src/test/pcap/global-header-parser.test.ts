import { describe, it, expect } from 'vitest';
import { parsePcapGlobalHeader } from '../../pcap/global-header-parser';
import { PcapGlobalHeader } from '../../pcap/global-header';
import { InvalidFileFormatError, BufferOutOfBoundsError } from '../../errors';

describe('parsePcapGlobalHeader', () => {
  const expectedHeaderBE: PcapGlobalHeader = {
    magic_number: 0xa1b2c3d4,
    version_major: 2,
    version_minor: 4,
    thiszone: 0,
    sigfigs: 0,
    snaplen: 65535,
    network: 1,
  };

  const expectedHeaderLE: PcapGlobalHeader = {
    magic_number: 0xd4c3b2a1,
    version_major: 2,
    version_minor: 4,
    thiszone: 0,
    sigfigs: 0,
    snaplen: 65535,
    network: 1,
  };

  // 24 bytes buffer
  // Magic Number (4 bytes): 0xa1b2c3d4
  // Version Major (2 bytes): 0x0002
  // Version Minor (2 bytes): 0x0004
  // Thiszone (4 bytes): 0x00000000
  // Sigfigs (4 bytes): 0x00000000
  // Snaplen (4 bytes): 0x0000ffff (65535)
  // Network (4 bytes): 0x00000001 (Ethernet)
  const validBigEndianData = Buffer.from([
    0xa1,
    0xb2,
    0xc3,
    0xd4, // magic_number
    0x00,
    0x02, // version_major
    0x00,
    0x04, // version_minor
    0x00,
    0x00,
    0x00,
    0x00, // thiszone
    0x00,
    0x00,
    0x00,
    0x00, // sigfigs
    0x00,
    0x00,
    0xff,
    0xff, // snaplen
    0x00,
    0x00,
    0x00,
    0x01, // network
  ]);

  // Same data, but little-endian magic number and byte order for other fields
  // Magic Number (4 bytes): 0xd4c3b2a1
  // Version Major (2 bytes): 0x0200
  // Version Minor (2 bytes): 0x0400
  // Thiszone (4 bytes): 0x00000000
  // Sigfigs (4 bytes): 0x00000000
  // Snaplen (4 bytes): 0xffff0000 (if read as BE, but it's LE so 0x0000ffff)
  // Network (4 bytes): 0x01000000 (if read as BE, but it's LE so 0x00000001)
  const validLittleEndianData = Buffer.from([
    0xd4,
    0xc3,
    0xb2,
    0xa1, // magic_number
    0x02,
    0x00, // version_major (LE)
    0x04,
    0x00, // version_minor (LE)
    0x00,
    0x00,
    0x00,
    0x00, // thiszone (LE)
    0x00,
    0x00,
    0x00,
    0x00, // sigfigs (LE)
    0xff,
    0xff,
    0x00,
    0x00, // snaplen (LE)
    0x01,
    0x00,
    0x00,
    0x00, // network (LE)
  ]);

  const invalidMagicNumberData = Buffer.from([
    0x1a,
    0x2b,
    0x3c,
    0x4d, // invalid magic_number
    0x00,
    0x02,
    0x00,
    0x04,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0xff,
    0xff,
    0x00,
    0x00,
    0x00,
    0x01,
  ]);

  const insufficientData = Buffer.from([0xa1, 0xb2, 0xc3, 0xd4, 0x00]); // Only 5 bytes

  it('should correctly parse a valid big-endian global header', () => {
    const header = parsePcapGlobalHeader(validBigEndianData);
    expect(header).toEqual(expectedHeaderBE);
  });

  it('should correctly parse a valid little-endian global header', () => {
    const header = parsePcapGlobalHeader(validLittleEndianData);
    // The magic number in the returned object should be the one read from the file (0xd4c3b2a1)
    expect(header).toEqual(expectedHeaderLE);
  });

  it('should throw InvalidFileFormatError for an invalid magic number', () => {
    expect(() => parsePcapGlobalHeader(invalidMagicNumberData)).toThrow(InvalidFileFormatError);
    expect(() => parsePcapGlobalHeader(invalidMagicNumberData)).toThrow(
      `Invalid magic number: 0x1a2b3c4d. Expected 0xa1b2c3d4 or 0xd4c3b2a1.`,
    );
  });

  it('should throw BufferOutOfBoundsError if the buffer is too small', () => {
    expect(() => parsePcapGlobalHeader(insufficientData)).toThrow(BufferOutOfBoundsError);
    // The actual message from the parser is "Buffer too small to contain PCAP Global Header. Expected 24 bytes."
    // The error message in the parser itself doesn't include the "got X bytes" part for this specific check.
    expect(() => parsePcapGlobalHeader(insufficientData)).toThrow(
      'Buffer too small to contain PCAP Global Header. Expected 24 bytes.',
    );
  });

  it('should throw BufferOutOfBoundsError for slightly too small buffer (23 bytes)', () => {
    const slightlyInsufficientData = Buffer.alloc(23); // One byte short
    expect(() => parsePcapGlobalHeader(slightlyInsufficientData)).toThrow(BufferOutOfBoundsError);
    expect(() => parsePcapGlobalHeader(slightlyInsufficientData)).toThrow(
      'Buffer too small to contain PCAP Global Header. Expected 24 bytes.',
    );
  });

  it('should correctly extract all fields for big-endian', () => {
    const data = Buffer.from([
      0xa1,
      0xb2,
      0xc3,
      0xd4, // magic_number
      0x12,
      0x34, // version_major = 0x1234 = 4660
      0x56,
      0x78, // version_minor = 0x5678 = 22136
      0x11,
      0x22,
      0x33,
      0x44, // thiszone = 0x11223344 (signed)
      0x55,
      0x66,
      0x77,
      0x88, // sigfigs = 0x55667788
      0xaa,
      0xbb,
      0xcc,
      0xdd, // snaplen = 0xaabbccdd
      0xee,
      0xff,
      0x00,
      0x11, // network = 0xeeff0011
    ]);
    const header = parsePcapGlobalHeader(data);
    expect(header.magic_number).toBe(0xa1b2c3d4);
    expect(header.version_major).toBe(0x1234);
    expect(header.version_minor).toBe(0x5678);
    expect(header.thiszone).toBe(0x11223344); // DataView handles signed conversion
    expect(header.sigfigs).toBe(0x55667788);
    expect(header.snaplen).toBe(0xaabbccdd);
    expect(header.network).toBe(0xeeff0011);
  });

  it('should correctly extract all fields for little-endian', () => {
    const data = Buffer.from([
      0xd4,
      0xc3,
      0xb2,
      0xa1, // magic_number
      0x34,
      0x12, // version_major = 0x1234
      0x78,
      0x56, // version_minor = 0x5678
      0x44,
      0x33,
      0x22,
      0x11, // thiszone = 0x11223344
      0x88,
      0x77,
      0x66,
      0x55, // sigfigs = 0x55667788
      0xdd,
      0xcc,
      0xbb,
      0xaa, // snaplen = 0xaabbccdd
      0x11,
      0x00,
      0xff,
      0xee, // network = 0xeeff0011
    ]);
    const header = parsePcapGlobalHeader(data);
    expect(header.magic_number).toBe(0xd4c3b2a1);
    expect(header.version_major).toBe(0x1234);
    expect(header.version_minor).toBe(0x5678);
    expect(header.thiszone).toBe(0x11223344);
    expect(header.sigfigs).toBe(0x55667788);
    expect(header.snaplen).toBe(0xaabbccdd);
    expect(header.network).toBe(0xeeff0011);
  });
});
