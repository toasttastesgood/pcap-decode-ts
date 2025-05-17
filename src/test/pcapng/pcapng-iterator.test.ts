import { Buffer } from 'buffer';
import { describe, it, expect, vi } from 'vitest';
import { iteratePcapNgPackets, PcapNgPacket } from '../../pcapng/pcapng-iterator';
import { PcapNgBlockType } from '../../pcapng/block-structures';
import * as logger from '../../utils/logger'; // To mock logger functions

// Mock the logger to prevent console output during tests and allow verification
vi.mock('../../utils/logger', () => ({
  logInfo: vi.fn(),
  logWarning: vi.fn(), // Corrected from logWarn
  logError: vi.fn(),
  setLogLevel: vi.fn(),
  getLogLevel: vi.fn(),
  LogLevel: { INFO: 3, WARN: 2, ERROR: 1, DEBUG: 4, NONE: 0 },
}));

describe('iteratePcapNgPackets', () => {
  // Helper function to create a simple SHB
  const createShb = (isBigEndian: boolean, sectionLength: bigint = 0xffffffffffffffffn): Buffer => {
    const buffer = Buffer.alloc(28); // Min SHB: type(4)+len(4)+magic(4)+maj(2)+min(2)+secLen(8)+len(4) = 28
    const writeUint32 = isBigEndian
      ? buffer.writeUInt32BE.bind(buffer)
      : buffer.writeUInt32LE.bind(buffer);
    const writeUint16 = isBigEndian
      ? buffer.writeUInt16BE.bind(buffer)
      : buffer.writeUInt16LE.bind(buffer);
    const writeBigInt64 = isBigEndian
      ? buffer.writeBigUInt64BE.bind(buffer)
      : buffer.writeBigUInt64LE.bind(buffer);

    writeUint32(PcapNgBlockType.SectionHeader, 0); // Block Type
    writeUint32(28, 4); // Block Total Length
    writeUint32(isBigEndian ? 0x1a2b3c4d : 0x4d3c2b1a, 8); // Byte Order Magic
    writeUint16(1, 12); // Major Version
    writeUint16(0, 14); // Minor Version
    writeBigInt64(sectionLength, 16); // Section Length (-1 means unspecified)
    writeUint32(28, 24); // Block Total Length (repeated)
    return buffer;
  };

  // Helper function to create a simple IDB
  const createIdb = (
    isBigEndian: boolean,
    linkType: number,
    snapLen: number = 0,
    // _interfaceIdForMap: number, // This parameter was unused
  ): Buffer => {
    // IDB: type(4)+len(4)+link(2)+res(2)+snap(4)+options(0)+len(4) = 20 (min, no options)
    const buffer = Buffer.alloc(20);
    const writeUint32 = isBigEndian
      ? buffer.writeUInt32BE.bind(buffer)
      : buffer.writeUInt32LE.bind(buffer);
    const writeUint16 = isBigEndian
      ? buffer.writeUInt16BE.bind(buffer)
      : buffer.writeUInt16LE.bind(buffer);

    writeUint32(PcapNgBlockType.InterfaceDescription, 0); // Block Type
    writeUint32(20, 4); // Block Total Length
    writeUint16(linkType, 8); // LinkType
    writeUint16(0, 10); // Reserved
    writeUint32(snapLen, 12); // SnapLen
    // No options for simplicity
    writeUint32(20, 16); // Block Total Length (repeated)
    return buffer;
  };

  // Helper function to create a simple EPB
  const createEpb = (
    isBigEndian: boolean,
    interfaceId: number,
    timestampHigh: number,
    timestampLow: number,
    capturedLength: number,
    originalLength: number,
    packetPayload: Buffer,
  ): Buffer => {
    const optionsLength = 0; // No options for simplicity
    const packetDataPadding = (4 - (capturedLength % 4)) % 4;
    // Block Total Length = 4 (BlockType) + 4 (BlockTotalLength1) +
    //                      4 (InterfaceID) + 4 (TimestampHigh) + 4 (TimestampLow) +
    //                      4 (CapturedLengthField) + 4 (OriginalLengthField) +
    //                      capturedLength (data) + packetDataPadding +
    //                      optionsLength (data) + 4 (BlockTotalLength2)
    //                   = 32 + capturedLength + packetDataPadding + optionsLength
    const blockTotalLength = 32 + capturedLength + packetDataPadding + optionsLength;
    const buffer = Buffer.alloc(blockTotalLength);
    const writeUint32 = isBigEndian
      ? buffer.writeUInt32BE.bind(buffer)
      : buffer.writeUInt32LE.bind(buffer);

    let offset = 0;
    writeUint32(PcapNgBlockType.EnhancedPacket, offset);
    offset += 4; // Block Type
    writeUint32(blockTotalLength, offset);
    offset += 4; // Block Total Length

    writeUint32(interfaceId, offset);
    offset += 4; // Interface ID
    writeUint32(timestampHigh, offset);
    offset += 4; // Timestamp High
    writeUint32(timestampLow, offset);
    offset += 4; // Timestamp Low
    writeUint32(capturedLength, offset);
    offset += 4; // Captured Packet Length
    writeUint32(originalLength, offset);
    offset += 4; // Original Packet Length

    packetPayload.copy(buffer, offset);
    offset += capturedLength; // Packet Data
    offset += packetDataPadding; // Skip padding

    // No options
    writeUint32(blockTotalLength, offset); // Block Total Length (repeated)
    return buffer;
  };

  it('should correctly iterate over a simple PCAPng file with one SHB, one IDB, and one EPB (Big Endian)', async () => {
    const shb = createShb(true);
    const idb = createIdb(true, 1, 0); // Linktype 1 (Ethernet), Snaplen 0
    const payload = Buffer.from([0x01, 0x02, 0x03, 0x04]);
    const epb = createEpb(true, 0, 100, 200, payload.length, payload.length, payload);

    const fileBuffer = Buffer.concat([shb, idb, epb]);
    const packets: PcapNgPacket[] = [];
    for await (const packet of iteratePcapNgPackets(fileBuffer)) {
      packets.push(packet);
    }

    expect(packets.length).toBe(1);
    const packet = packets[0];
    expect(packet.interface_id).toBe(0);
    expect(packet.interface_link_type).toBe(1);
    expect(packet.timestamp).toBe((BigInt(100) << 32n) | BigInt(200));
    expect(packet.capturedLength).toBe(payload.length);
    expect(packet.originalLength).toBe(payload.length);
    expect(packet.packetData).toEqual(payload);
    expect(logger.logWarning).not.toHaveBeenCalled();
    expect(logger.logError).not.toHaveBeenCalled();
  });

  it('should correctly iterate over a simple PCAPng file with one SHB, one IDB, and one EPB (Little Endian)', async () => {
    const shb = createShb(false);
    const idb = createIdb(false, 1, 0);
    const payload = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
    const epb = createEpb(false, 0, 300, 400, payload.length, payload.length, payload);

    const fileBuffer = Buffer.concat([shb, idb, epb]);
    const packets: PcapNgPacket[] = [];
    for await (const packet of iteratePcapNgPackets(fileBuffer)) {
      packets.push(packet);
    }

    expect(packets.length).toBe(1);
    const packet = packets[0];
    expect(packet.interface_id).toBe(0);
    expect(packet.interface_link_type).toBe(1);
    expect(packet.timestamp).toBe((BigInt(300) << 32n) | BigInt(400));
    expect(packet.capturedLength).toBe(payload.length);
    expect(packet.originalLength).toBe(payload.length);
    expect(packet.packetData).toEqual(payload);
    expect(logger.logWarning).not.toHaveBeenCalled();
    expect(logger.logError).not.toHaveBeenCalled();
  });

  it('should handle multiple EPBs for the same interface', async () => {
    const shb = createShb(true);
    const idb = createIdb(true, 1, 0);
    const payload1 = Buffer.from([0x01, 0x02]);
    const epb1 = createEpb(true, 0, 10, 20, payload1.length, payload1.length, payload1);
    const payload2 = Buffer.from([0x03, 0x04, 0x05]);
    const epb2 = createEpb(true, 0, 30, 40, payload2.length, payload2.length, payload2);

    const fileBuffer = Buffer.concat([shb, idb, epb1, epb2]);
    const packets: PcapNgPacket[] = [];
    for await (const packet of iteratePcapNgPackets(fileBuffer)) {
      packets.push(packet);
    }

    expect(packets.length).toBe(2);
    expect(packets[0].packetData).toEqual(payload1);
    expect(packets[0].timestamp).toBe((BigInt(10) << 32n) | BigInt(20));
    expect(packets[1].packetData).toEqual(payload2);
    expect(packets[1].timestamp).toBe((BigInt(30) << 32n) | BigInt(40));
    expect(logger.logError).not.toHaveBeenCalled();
  });

  it('should handle multiple interfaces and associate packets correctly', async () => {
    const shb = createShb(true);
    const idb0 = createIdb(true, 1, 0); // Interface 0, Ethernet
    const idb1 = createIdb(true, 101, 0); // Interface 1, Raw IP

    const payload0 = Buffer.from([0xaa]);
    const epb0 = createEpb(true, 0, 1000, 1, payload0.length, payload0.length, payload0); // For interface 0

    const payload1 = Buffer.from([0xbb, 0xcc]);
    const epb1 = createEpb(true, 1, 2000, 2, payload1.length, payload1.length, payload1); // For interface 1

    const fileBuffer = Buffer.concat([shb, idb0, idb1, epb0, epb1]);
    const packets: PcapNgPacket[] = [];
    for await (const packet of iteratePcapNgPackets(fileBuffer)) {
      packets.push(packet);
    }

    expect(packets.length).toBe(2);
    const packetForId0 = packets.find((p) => p.interface_id === 0);
    const packetForId1 = packets.find((p) => p.interface_id === 1);

    expect(packetForId0).toBeDefined();
    expect(packetForId0?.interface_link_type).toBe(1);
    expect(packetForId0?.packetData).toEqual(payload0);

    expect(packetForId1).toBeDefined();
    expect(packetForId1?.interface_link_type).toBe(101);
    expect(packetForId1?.packetData).toEqual(payload1);
    expect(logger.logError).not.toHaveBeenCalled();
  });

  it('should skip unknown block types and log a warning', async () => {
    const shb = createShb(true);
    const unknownBlock = Buffer.alloc(20);
    const writeUint32 = unknownBlock.writeUInt32BE.bind(unknownBlock);
    writeUint32(0xbadbeef, 0); // Unknown block type
    writeUint32(20, 4); // Block total length
    // ... fill with some data ...
    writeUint32(20, 16); // Repeated block total length

    const idb = createIdb(true, 1, 0);
    const payload = Buffer.from([0xca, 0xfe]);
    const epb = createEpb(true, 0, 5, 5, payload.length, payload.length, payload);

    const fileBuffer = Buffer.concat([shb, unknownBlock, idb, epb]);
    const packets: PcapNgPacket[] = [];
    for await (const packet of iteratePcapNgPackets(fileBuffer)) {
      packets.push(packet);
    }

    expect(packets.length).toBe(1); // Should only get the EPB
    expect(packets[0].packetData).toEqual(payload);
    expect(logger.logWarning).toHaveBeenCalledWith(
      expect.stringContaining('Unknown or unhandled block type: 0xbadbeef'),
    );
    expect(logger.logError).not.toHaveBeenCalled();
  });

  it('should handle a file with only SHB and IDB (no packets)', async () => {
    const shb = createShb(true);
    const idb = createIdb(true, 1, 0);
    const fileBuffer = Buffer.concat([shb, idb]);
    const packets: PcapNgPacket[] = [];
    for await (const packet of iteratePcapNgPackets(fileBuffer)) {
      packets.push(packet);
    }
    expect(packets.length).toBe(0);
    expect(logger.logError).not.toHaveBeenCalled();
  });

  it('should handle byte order change between sections', async () => {
    const shb1 = createShb(true); // Section 1: Big Endian
    const idb1 = createIdb(true, 1, 0);
    const payload1 = Buffer.from([0x01, 0x02]);
    const epb1 = createEpb(true, 0, 10, 20, payload1.length, payload1.length, payload1);

    const shb2 = createShb(false); // Section 2: Little Endian
    const idb2 = createIdb(false, 2, 0); // Interface ID will be 0 for this new section
    const payload2 = Buffer.from([0x03, 0x04]);
    const epb2 = createEpb(false, 0, 30, 40, payload2.length, payload2.length, payload2);

    const fileBuffer = Buffer.concat([shb1, idb1, epb1, shb2, idb2, epb2]);
    const packets: PcapNgPacket[] = [];
    for await (const packet of iteratePcapNgPackets(fileBuffer)) {
      packets.push(packet);
    }

    expect(packets.length).toBe(2);
    expect(packets[0].interface_link_type).toBe(1);
    expect(packets[0].packetData).toEqual(payload1);
    expect(packets[0].timestamp).toBe((BigInt(10) << 32n) | BigInt(20));

    expect(packets[1].interface_link_type).toBe(2);
    expect(packets[1].packetData).toEqual(payload2);
    expect(packets[1].timestamp).toBe((BigInt(30) << 32n) | BigInt(40));
    expect(logger.logError).not.toHaveBeenCalled();
  });

  it('should log an error and stop if SHB is missing at the beginning', async () => {
    const idb = createIdb(true, 1, 0); // No SHB
    const fileBuffer = Buffer.concat([idb]);
    const packets: PcapNgPacket[] = [];
    for await (const packet of iteratePcapNgPackets(fileBuffer)) {
      packets.push(packet);
    }
    expect(packets.length).toBe(0);
    expect(logger.logError).toHaveBeenCalledWith(
      expect.stringContaining('Invalid or missing Section Header Block'),
    );
  });

  it('should log an error and skip packet if EPB references non-existent interface ID', async () => {
    const shb = createShb(true);
    const idb = createIdb(true, 1, 0); // Defines interface 0
    const payload = Buffer.from([0x01, 0x02, 0x03, 0x04]);
    // EPB references interface 1, which is not defined
    const epb = createEpb(true, 1, 100, 200, payload.length, payload.length, payload);

    const fileBuffer = Buffer.concat([shb, idb, epb]);
    const packets: PcapNgPacket[] = [];
    for await (const packet of iteratePcapNgPackets(fileBuffer)) {
      packets.push(packet);
    }

    expect(packets.length).toBe(0);
    expect(logger.logWarning).toHaveBeenCalledWith(
      expect.stringContaining(
        'EPB at offset 48 references unknown Interface ID: 1. Skipping packet.',
      ),
    );
  });

  it('should handle truncated file where a block header is incomplete', async () => {
    const shb = createShb(true);
    const truncatedFile = shb.subarray(0, shb.length - 10); // Truncate SHB itself

    const packets: PcapNgPacket[] = [];
    for await (const packet of iteratePcapNgPackets(truncatedFile)) {
      packets.push(packet);
    }
    expect(packets.length).toBe(0);
    // The initial SHB check might fail, or the generic block parser might fail.
    // If initial SHB check fails:
    // expect(logger.logError).toHaveBeenCalledWith(expect.stringContaining('Invalid or missing Section Header Block'));
    // If generic block parser fails:
    expect(logger.logWarning).toHaveBeenCalledWith(
      expect.stringContaining('Insufficient data for a new block header at offset'),
    );
  });

  it('should handle truncated file where block_total_length exceeds buffer', async () => {
    const shbBuffer = createShb(true); // 28 bytes
    // Modify block_total_length to be larger than available buffer
    const modifiedShb = Buffer.from(shbBuffer);
    // Assuming BE for this test modification
    modifiedShb.writeUInt32BE(1000, 4); // Set block_total_length to 1000
    modifiedShb.writeUInt32BE(1000, 24); // Set trailing block_total_length to 1000
    // File buffer is only 28 bytes, but block claims 1000
    const fileBuffer = modifiedShb;

    const packets: PcapNgPacket[] = [];
    for await (const packet of iteratePcapNgPackets(fileBuffer)) {
      packets.push(packet);
    }
    expect(packets.length).toBe(0);
    expect(logger.logWarning).toHaveBeenCalledWith(
      expect.stringContaining(
        // The message from parsePcapNgGenericBlock is "Insufficient data for full block at offset 0. Declared length 1000, available 28."
        // The iterator wraps this: "Error parsing generic block header at offset 0: Insufficient data for full block at offset 0. Declared length 1000, available 28.. Attempting to skip 4 bytes."
        'Error parsing generic block header at offset 0: Insufficient data for full block at offset 0. Declared length 1000, available 28. Attempting to skip 4 bytes.',
      ),
    );
  });

  it('should gracefully skip a malformed block (e.g., bad specific block parsing) and continue', async () => {
    const shb = createShb(true);
    const idb = createIdb(true, 1, 0);

    // Create a "malformed" EPB - e.g., captured_len > actual data in body
    // For this test, we'll make a block that *looks* like an EPB by type,
    // but whose body will cause parseEnhancedPacketBlock to fail if it had more complex checks.
    // Or, more simply, a block that is valid generically but fails specific parsing.
    // Let's simulate a block that is generically valid but we'll mock its specific parser to throw.
 
    // This block declares its total length as 32 (see writeUint32(32, offset) below),
    // so the buffer must be allocated accordingly.
    const malformedEpbData = Buffer.alloc(32);
    const writeUint32 = malformedEpbData.writeUInt32BE.bind(malformedEpbData);
    let offset = 0;
    writeUint32(PcapNgBlockType.EnhancedPacket, offset);
    offset += 4; // Type
    writeUint32(32, offset);
    offset += 4; // Total length (e.g. 8 header + 20 body + 4 footer)
    writeUint32(0, offset);
    offset += 4; // Interface ID
    writeUint32(0, offset);
    offset += 4; // Timestamp H
    writeUint32(0, offset);
    offset += 4; // Timestamp L
    writeUint32(1, offset);
    offset += 4; // Captured len (e.g. 1 byte)
    writeUint32(1, offset);
    offset += 4; // Original len
    // Missing packet data of 1 byte + padding + options
    // This will cause parseEnhancedPacketBlock to throw if it tries to read packet_data
    // The block body passed to parseEnhancedPacketBlock will be 32 - 8 - 4 = 20 bytes.
    // It expects captured_len (1 byte) to be readable from this 20-byte body.
    // Let's make captured_len larger than the body it will receive.
    // Body will be from offset 8 to 32-4 = 28. So body is 20 bytes.
    // If captured_len is 21, it will fail.
    malformedEpbData.writeUInt32BE(21, 16); // Captured len = 21, but body is only 20.

    // Add the trailing length
    malformedEpbData.writeUInt32BE(32, 28); // Total length repeated

    const goodPayload = Buffer.from([0xde, 0xad]);
    const goodEpb = createEpb(
      true,
      0,
      200,
      300,
      goodPayload.length,
      goodPayload.length,
      goodPayload,
    );

    const fileBuffer = Buffer.concat([shb, idb, malformedEpbData, goodEpb]);

    const packets: PcapNgPacket[] = [];
    for await (const packet of iteratePcapNgPackets(fileBuffer)) {
      packets.push(packet);
    }

    expect(packets.length).toBe(1); // Should get the good EPB
    expect(packets[0].packetData).toEqual(goodPayload);
    // The error from parseEnhancedPacketBlock: "EPB captured_len (21) at offset 16 exceeds block body bounds (blockBody length 20)."
    // The iterator wraps this: "Error parsing specific block type 0x6 (total length 32) at offset 48: EPB captured_len (21) at offset 16 exceeds block body bounds (blockBody length 20). Skipping block."
    expect(logger.logWarning).toHaveBeenCalledWith(
      expect.stringContaining(
        'Error parsing specific block type 0x6 (total length 32) at offset 48: EPB captured_len (21) at offset 16 exceeds block body bounds (blockBody length 20). Skipping block.',
      ),
    );
  });

  // TODO: Add tests for SimplePacketBlock once its parser is available and integrated.
  // TODO: Add tests for InterfaceStatisticsBlock once its parser is available and integrated.
  // TODO: Add tests for NameResolutionBlock processing (if state needs to be checked).
  // TODO: Add tests for options within blocks (e.g., if_name in IDB affecting output PcapNgPacket).
  // TODO: Test with actual sample PCAPng files (requires file loading mechanism or embedding).
});
