import { describe, it, expect, vi } from 'vitest';
import { Buffer } from 'buffer';
import { iteratePcapPackets, PcapPacket } from '../../pcap/pcap-iterator';
import { PcapError, PcapParsingError } from '../../errors';
import * as logger from '../../utils/logger';

// Helper function to create a Buffer from a hex string
const hexToBuffer = (hex: string): Buffer => Buffer.from(hex.replace(/\s/g, ''), 'hex');

// Standard Little Endian Global Header
// magic_number: 0xa1b2c3d4 (little-endian: d4 c3 b2 a1)
// version_major: 2 (02 00)
// version_minor: 4 (04 00)
// thiszone: 0 (00 00 00 00)
// sigfigs: 0 (00 00 00 00)
// snaplen: 65535 (ff ff 00 00)
// network: 1 (Ethernet) (01 00 00 00)
const defaultGlobalHeaderLE =
  'd4 c3 b2 a1 02 00 04 00 00 00 00 00 00 00 00 00 ff ff 00 00 01 00 00 00';

// Standard Big Endian Global Header
// magic_number: 0xa1b2c3d4 (big-endian: a1 b2 c3 d4)
const defaultGlobalHeaderBE =
  'a1 b2 c3 d4 00 02 00 04 00 00 00 00 00 00 00 00 00 00 ff ff 00 00 00 01';

describe('iteratePcapPackets', () => {
  it('should correctly iterate over all packets in a valid little-endian PCAP buffer', async () => {
    const packetsData = [
      { ts_sec: 1600000000, ts_usec: 100, incl_len: 4, orig_len: 4, data: '01 02 03 04' },
      { ts_sec: 1600000001, ts_usec: 200, incl_len: 6, orig_len: 6, data: '05 06 07 08 09 0a' },
    ];

    let pcapHex = defaultGlobalHeaderLE;
    for (const pkt of packetsData) {
      pcapHex += ` ${Buffer.from(new Uint32Array([pkt.ts_sec]).buffer).toString('hex')} `;
      pcapHex += ` ${Buffer.from(new Uint32Array([pkt.ts_usec]).buffer).toString('hex')} `;
      pcapHex += ` ${Buffer.from(new Uint32Array([pkt.incl_len]).buffer).toString('hex')} `;
      pcapHex += ` ${Buffer.from(new Uint32Array([pkt.orig_len]).buffer).toString('hex')} `;
      pcapHex += ` ${pkt.data.replace(/\s/g, '')} `;
    }
    const pcapBuffer = hexToBuffer(pcapHex);

    const iteratedPackets: PcapPacket[] = [];
    for await (const packet of iteratePcapPackets(pcapBuffer)) {
      iteratedPackets.push(packet);
    }

    expect(iteratedPackets.length).toBe(packetsData.length);
    for (let i = 0; i < packetsData.length; i++) {
      expect(iteratedPackets[i].header.ts_sec).toBe(packetsData[i].ts_sec);
      expect(iteratedPackets[i].header.ts_usec).toBe(packetsData[i].ts_usec);
      expect(iteratedPackets[i].header.incl_len).toBe(packetsData[i].incl_len);
      expect(iteratedPackets[i].header.orig_len).toBe(packetsData[i].orig_len);
      expect(iteratedPackets[i].packetData.toString('hex')).toBe(
        packetsData[i].data.replace(/\s/g, ''),
      );
    }
  });

  it('should correctly iterate over all packets in a valid big-endian PCAP buffer', async () => {
    const packetsData = [
      { ts_sec: 1700000000, ts_usec: 300, incl_len: 2, orig_len: 2, data: 'aa bb' },
    ];

    let pcapHex = defaultGlobalHeaderBE;
    for (const pkt of packetsData) {
      const tsSecBuf = Buffer.alloc(4);
      tsSecBuf.writeUInt32BE(pkt.ts_sec, 0);
      pcapHex += ` ${tsSecBuf.toString('hex')} `;

      const tsUsecBuf = Buffer.alloc(4);
      tsUsecBuf.writeUInt32BE(pkt.ts_usec, 0);
      pcapHex += ` ${tsUsecBuf.toString('hex')} `;

      const inclLenBuf = Buffer.alloc(4);
      inclLenBuf.writeUInt32BE(pkt.incl_len, 0);
      pcapHex += ` ${inclLenBuf.toString('hex')} `;

      const origLenBuf = Buffer.alloc(4);
      origLenBuf.writeUInt32BE(pkt.orig_len, 0);
      pcapHex += ` ${origLenBuf.toString('hex')} `;
      pcapHex += ` ${pkt.data.replace(/\s/g, '')} `;
    }
    const pcapBuffer = hexToBuffer(pcapHex);

    const iteratedPackets: PcapPacket[] = [];
    for await (const packet of iteratePcapPackets(pcapBuffer)) {
      iteratedPackets.push(packet);
    }

    expect(iteratedPackets.length).toBe(packetsData.length);
    expect(iteratedPackets[0].header.ts_sec).toBe(packetsData[0].ts_sec);
    expect(iteratedPackets[0].header.ts_usec).toBe(packetsData[0].ts_usec);
    expect(iteratedPackets[0].header.incl_len).toBe(packetsData[0].incl_len);
    expect(iteratedPackets[0].header.orig_len).toBe(packetsData[0].orig_len);
    expect(iteratedPackets[0].packetData.toString('hex')).toBe(
      packetsData[0].data.replace(/\s/g, ''),
    );
  });

  it('should handle an empty PCAP file (only global header)', async () => {
    const pcapBuffer = hexToBuffer(defaultGlobalHeaderLE);
    const iteratedPackets: PcapPacket[] = [];
    for await (const packet of iteratePcapPackets(pcapBuffer)) {
      iteratedPackets.push(packet);
    }
    expect(iteratedPackets.length).toBe(0);
  });

  it('should handle PCAP file with zero-length packets', async () => {
    const packetsData = [{ ts_sec: 1600000000, ts_usec: 100, incl_len: 0, orig_len: 0, data: '' }];
    let pcapHex = defaultGlobalHeaderLE;
    for (const pkt of packetsData) {
      pcapHex += ` ${Buffer.from(new Uint32Array([pkt.ts_sec]).buffer).toString('hex')} `;
      pcapHex += ` ${Buffer.from(new Uint32Array([pkt.ts_usec]).buffer).toString('hex')} `;
      pcapHex += ` ${Buffer.from(new Uint32Array([pkt.incl_len]).buffer).toString('hex')} `;
      pcapHex += ` ${Buffer.from(new Uint32Array([pkt.orig_len]).buffer).toString('hex')} `;
      // No data for zero-length packet
    }
    const pcapBuffer = hexToBuffer(pcapHex);

    const iteratedPackets: PcapPacket[] = [];
    for await (const packet of iteratePcapPackets(pcapBuffer)) {
      iteratedPackets.push(packet);
    }

    expect(iteratedPackets.length).toBe(1);
    expect(iteratedPackets[0].header.incl_len).toBe(0);
    expect(iteratedPackets[0].packetData.length).toBe(0);
  });

  it('should throw PcapError for a PCAP buffer too short for global header', async () => {
    const pcapBuffer = hexToBuffer('d4 c3 b2 a1'); // Too short
    try {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      for await (const packet of iteratePcapPackets(pcapBuffer)) {
        // Should not reach here
      }
      throw new Error('Should have thrown PcapError for too short global header');
    } catch (e) {
      expect(e).toBeInstanceOf(PcapError);
      expect((e as PcapError).message).toContain(
        'PCAP data is too short to contain a global header.',
      );
    }
  });

  it('should yield no packets and log warning for a truncated file after global header (not enough for packet header)', async () => {
    const logWarningSpy = vi.spyOn(logger, 'logWarning');
    const pcapBuffer = hexToBuffer(defaultGlobalHeaderLE + '01 02 03 04'); // Global header + 4 bytes (not 16)
    const iteratedPackets: PcapPacket[] = [];
    for await (const packet of iteratePcapPackets(pcapBuffer)) {
      iteratedPackets.push(packet);
    }
    expect(iteratedPackets.length).toBe(0);
    expect(logWarningSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        'Truncated PCAP data at offset 24: expected 16 bytes for packet header, got 4 bytes. Stopping iteration.',
      ),
    );
    logWarningSpy.mockRestore();
  });

  it('should skip a corrupted packet (insufficient data for incl_len) and log warning, then process subsequent valid packets', async () => {
    const logWarningSpy = vi.spyOn(logger, 'logWarning');
    let pcapHex = defaultGlobalHeaderLE;
    // Corrupted Packet 1: incl_len=10, but only 5 bytes of data provided
    pcapHex += ' 01000000 01000000 0a000000 0a000000'; // ts_sec, ts_usec, incl_len=10, orig_len=10
    pcapHex += ' 0102030405'; // Only 5 bytes of data

    // Valid Packet 2
    const validPacketData = {
      ts_sec: 1600000002,
      ts_usec: 300,
      incl_len: 2,
      orig_len: 2,
      data: 'BEEF',
    };
    pcapHex += ` ${Buffer.from(new Uint32Array([validPacketData.ts_sec]).buffer).toString('hex')} `;
    pcapHex += ` ${Buffer.from(new Uint32Array([validPacketData.ts_usec]).buffer).toString('hex')} `;
    pcapHex += ` ${Buffer.from(new Uint32Array([validPacketData.incl_len]).buffer).toString('hex')} `;
    pcapHex += ` ${Buffer.from(new Uint32Array([validPacketData.orig_len]).buffer).toString('hex')} `;
    pcapHex += ` ${validPacketData.data} `;

    const pcapBuffer = hexToBuffer(pcapHex);
    const iteratedPackets: PcapPacket[] = [];
    for await (const packet of iteratePcapPackets(pcapBuffer)) {
      iteratedPackets.push(packet);
    }

    expect(logWarningSpy).toHaveBeenCalledWith(
      expect.stringContaining('Skipping corrupted PCAP packet at offset 24:'),
    );
    expect(logWarningSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        'Insufficient buffer size to read packet data at offset 40. Need 10 bytes for data, got 5.',
      ),
    );
    expect(logWarningSpy).toHaveBeenCalledWith(
      expect.stringContaining('Attempting to advance 16 bytes to find next packet.'),
    );

    expect(iteratedPackets.length).toBe(1); // Should have skipped the first and processed the second
    expect(iteratedPackets[0].header.ts_sec).toBe(validPacketData.ts_sec);
    expect(iteratedPackets[0].header.incl_len).toBe(validPacketData.incl_len);
    expect(iteratedPackets[0].packetData.toString('hex').toUpperCase()).toBe(validPacketData.data);

    logWarningSpy.mockRestore();
  });

  it('should throw PcapError if parsePcapGlobalHeader throws (e.g. bad magic number)', async () => {
    // Create a buffer with an invalid magic number that parsePcapGlobalHeader would reject
    const invalidGlobalHeader =
      '00 00 00 00 02 00 04 00 00 00 00 00 00 00 00 00 ff ff 00 00 01 00 00 00';
    const pcapBuffer = hexToBuffer(invalidGlobalHeader);

    // Mock or ensure parsePcapGlobalHeader throws/returns null for this.
    // The actual parsePcapGlobalHeader should throw PcapError for invalid magic number.
    // This test verifies iteratePcapPackets correctly propagates errors from parsePcapGlobalHeader.
    await expect(async () => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      for await (const packet of iteratePcapPackets(pcapBuffer)) {
        // Should not reach here
      }
    }).rejects.toThrow(PcapError); // Or more specifically InvalidFileFormatError

    try {
      for await (const packet of iteratePcapPackets(pcapBuffer)) {}
    } catch (e) {
      expect(e).toBeInstanceOf(PcapError); // PcapError or its subclass InvalidFileFormatError
      expect((e as PcapError).message).toContain('Invalid magic number');
    }
  });

  it('should skip a packet if its header is malformed (e.g., not enough bytes for header fields)', async () => {
    const logWarningSpy = vi.spyOn(logger, 'logWarning');
    let pcapHex = defaultGlobalHeaderLE;

    // Malformed Packet Header (only 10 bytes instead of 16)
    pcapHex += ' 01000000 01000000 0a00'; // ts_sec, ts_usec, part of incl_len

    // Valid Packet 2
    const validPacketData = {
      ts_sec: 1600000003,
      ts_usec: 400,
      incl_len: 3,
      orig_len: 3,
      data: 'C0FFEE',
    };
    // Add some padding to ensure the valid packet is far enough away if the skip logic is naive
    pcapHex += ' AABBAABBCCDD'; // Some garbage to ensure the skip logic works
    const validPacketOffset = hexToBuffer(pcapHex).length;

    pcapHex += ` ${Buffer.from(new Uint32Array([validPacketData.ts_sec]).buffer).toString('hex')} `;
    pcapHex += ` ${Buffer.from(new Uint32Array([validPacketData.ts_usec]).buffer).toString('hex')} `;
    pcapHex += ` ${Buffer.from(new Uint32Array([validPacketData.incl_len]).buffer).toString('hex')} `;
    pcapHex += ` ${Buffer.from(new Uint32Array([validPacketData.orig_len]).buffer).toString('hex')} `;
    pcapHex += ` ${validPacketData.data} `;

    const pcapBuffer = hexToBuffer(pcapHex);
    const iteratedPackets: PcapPacket[] = [];

    // Manually calculate the offset of the second (valid) packet for assertion
    // Global header (24) + malformed part (10) + padding (6) = 40
    // The iterator tries to read packet header at offset 24. It fails.
    // It should then advance by 16 bytes (default skip for header error).
    // New offset = 24 + 16 = 40. This is where the valid packet starts.

    for await (const packet of iteratePcapPackets(pcapBuffer)) {
      iteratedPackets.push(packet);
    }

    expect(logWarningSpy).toHaveBeenCalledWith(
      expect.stringContaining('Skipping corrupted PCAP packet at offset 24:'),
    );
    // The error message from parsePcapPacketRecord for a short header
    expect(logWarningSpy).toHaveBeenCalledWith(
      expect.stringContaining(
        'Insufficient buffer size to read packet record header at offset 24. Need 16 bytes, got 10.',
      ),
    );
    expect(logWarningSpy).toHaveBeenCalledWith(
      expect.stringContaining('Attempting to advance 16 bytes to find next packet.'),
    );

    expect(iteratedPackets.length).toBe(1);
    expect(iteratedPackets[0].header.ts_sec).toBe(validPacketData.ts_sec);
    expect(iteratedPackets[0].packetData.toString('hex').toUpperCase()).toBe(validPacketData.data);

    logWarningSpy.mockRestore();
  });
});
