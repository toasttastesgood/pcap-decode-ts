import { describe, it, expect } from 'vitest';
import { Buffer } from 'buffer';
import { iteratePcapPackets, PcapPacket } from '../../pcap/pcap-iterator';
import { PcapError } from '../../errors';

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

  it('should throw PcapError for a truncated file after global header (not enough for packet header)', async () => {
    const pcapBuffer = hexToBuffer(defaultGlobalHeaderLE + '01 02 03 04'); // Global header + 4 bytes (not 16)
    try {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      for await (const packet of iteratePcapPackets(pcapBuffer)) {
        // Should not reach here
      }
      throw new Error('Should have thrown PcapError for truncated packet header');
    } catch (e) {
      expect(e).toBeInstanceOf(PcapError);
      expect((e as PcapError).message).toContain(
        'Truncated PCAP data: expected 16 bytes for packet header',
      );
    }
  });

  it('should throw PcapError for a truncated file mid-packet (not enough for packet data)', async () => {
    let pcapHex = defaultGlobalHeaderLE;
    // Packet header: ts_sec=1, ts_usec=1, incl_len=10, orig_len=10
    pcapHex += ' 01000000 01000000 0a000000 0a000000';
    // Packet data: only 5 bytes instead of 10
    pcapHex += ' 0102030405';
    const pcapBuffer = hexToBuffer(pcapHex);

    try {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      for await (const packet of iteratePcapPackets(pcapBuffer)) {
        // Should not reach here
      }
      throw new Error('Should have thrown PcapError for truncated packet data');
    } catch (e) {
      expect(e).toBeInstanceOf(PcapError);
      expect((e as PcapError).message).toContain('Truncated packet data at offset');
      expect((e as PcapError).message).toContain('expected 10 bytes for packet data');
    }
  });

  it('should throw PcapError if parsePcapGlobalHeader returns null (simulating bad magic number or other critical failure)', async () => {
    // Create a buffer with an invalid magic number that parsePcapGlobalHeader would reject
    const invalidGlobalHeader =
      '00 00 00 00 02 00 04 00 00 00 00 00 00 00 00 00 ff ff 00 00 01 00 00 00';
    const pcapBuffer = hexToBuffer(invalidGlobalHeader);

    // Mock or ensure parsePcapGlobalHeader throws/returns null for this.
    // The actual parsePcapGlobalHeader should throw PcapError for invalid magic number.
    // This test verifies iteratePcapPackets handles the case where global header parsing fails.
    try {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      for await (const packet of iteratePcapPackets(pcapBuffer)) {
        // Should not reach here
      }
      throw new Error('Should have thrown PcapError due to global header parsing failure');
    } catch (e) {
      expect(e).toBeInstanceOf(PcapError);
      // The error message might come from parsePcapGlobalHeader itself or the iterator's check.
      // Example: "Invalid PCAP magic number" or "Failed to parse PCAP global header."
      expect((e as PcapError).message).toMatch(
        /Invalid PCAP magic number|Failed to parse PCAP global header/,
      );
    }
  });
});
