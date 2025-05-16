import { Buffer } from 'buffer'; // Standard Node.js Buffer
import {
  PcapNgInterfaceDescriptionBlock,
  PcapNgBlockType,
  // type PcapNgBlock, // This generic type might not be needed here if using specific blocks
} from './block-structures';
import { parsePcapNgGenericBlock, ParsedPcapNgGenericBlock } from './generic-block-parser';
import {
  parseSectionHeaderBlock,
  parseInterfaceDescriptionBlock,
  parseEnhancedPacketBlock,
  // parseSimplePacketBlock, // Not currently exported from block-parsers.ts
  parseNameResolutionBlock,
  // parseInterfaceStatisticsBlock, // Not currently exported from block-parsers.ts
} from './block-parsers';
import { PcapParsingError, BufferOutOfBoundsError } from '../errors'; // Assuming PcapNgDecodingError was a typo for PcapParsingError
import { logInfo, logWarning, logError } from '../utils/logger'; // Import specific logger functions

// Create a logger-like object for convenience
const logger = {
  info: logInfo,
  warn: logWarning, // Corrected from logWarn to logWarning
  error: logError,
};

/**
 * Represents a parsed PCAPng packet, including its metadata and data.
 */
export interface PcapNgPacket {
  /** The ID of the interface on which this packet was captured. */
  interface_id: number;
  /** The link layer type of the interface (e.g., LINKTYPE_ETHERNET). */
  interface_link_type: number;
  /** The timestamp of packet capture, as a BigInt representing nanoseconds or other resolution defined by if_tsresol option. */
  timestamp: bigint; // Combined high and low
  /** The number of bytes captured from the packet and stored in packetData. */
  capturedLength: number;
  /** The actual length of the packet on the network when it was transmitted. */
  originalLength: number;
  /** The captured packet data. */
  packetData: Buffer;
  /** Optional name of the interface, if available from IDB options. */
  interface_name?: string;
  /** Optional description of the interface, if available from IDB options. */
  interface_description?: string;
}

/**
 * Internal state for the PCAPng iterator.
 * @internal
 */
interface IteratorState {
  /** Current byte order for parsing blocks in the current section. True if big-endian. */
  currentByteOrderIsBigEndian: boolean;
  /** Map of interface IDs to their Interface Description Blocks. */
  interfaces: Map<number, PcapNgInterfaceDescriptionBlock>;
  // Potentially other state like name resolutions
}

/**
 * Asynchronously iterates over a PCAPng file buffer and yields individual packets.
 * It processes Section Header Blocks (SHB) to determine endianness and Interface Description Blocks (IDB)
 * to understand packet link types. It primarily yields packets from Enhanced Packet Blocks (EPB).
 * Other block types are parsed or skipped as appropriate.
 *
 * @param fileBuffer - The buffer containing the PCAPng file data.
 * @returns An async generator yielding {@link PcapNgPacket} objects.
 * @throws {PcapParsingError} If critical errors occur during parsing, such as an invalid initial SHB.
 *                            Non-critical errors parsing individual blocks might be logged and skipped.
 */
export async function* iteratePcapNgPackets(
  fileBuffer: Buffer,
): AsyncGenerator<PcapNgPacket, void, undefined> {
  let offset = 0;
  const state: IteratorState = {
    currentByteOrderIsBigEndian: true, // Default to big-endian, will be set by the first SHB
    interfaces: new Map(),
  };

  logger.info('Starting PCAPng packet iteration.');

  // First, attempt to read the first SHB to determine endianness for subsequent generic block parsing.
  // This is a bit of a chicken-and-egg problem. The SHB's byte_order_magic tells us the endianness,
  // but to read byte_order_magic, we need to know the endianness.
  // PCAPng spec: "the byte_order_magic is used to distinguish sections written in little-endian
  // format from sections written in big-endian format."
  // This implies we can read the magic number assuming one endianness, and if it matches, we're good.
  // If not, we try the other. The first block MUST be an SHB.

  if (fileBuffer.length < 12) {
    // Minimum SHB size (Block Type, Total Length, Magic, Versions, Section Length, Trailing Length)
    logger.error('File too short to contain a valid Section Header Block.');
    return;
  }

  // Try reading byte_order_magic as big-endian first
  let initialMagic = fileBuffer.readUInt32BE(offset + 8); // SHB: type(4) + length(4) + magic(here)
  if (initialMagic === 0x1a2b3c4d) {
    state.currentByteOrderIsBigEndian = true;
  } else {
    initialMagic = fileBuffer.readUInt32LE(offset + 8);
    if (initialMagic === 0x1a2b3c4d) {
      state.currentByteOrderIsBigEndian = false;
    } else {
      logger.error(
        'Invalid or missing Section Header Block at the beginning of the file. Cannot determine byte order.',
      );
      return;
    }
  }
  logger.info(
    `Initial byte order determined: ${state.currentByteOrderIsBigEndian ? 'big-endian' : 'little-endian'}`,
  );

  while (offset < fileBuffer.length) {
    if (fileBuffer.length - offset < 8) {
      // Minimum size for block type and total length
      logger.warn(
        `Insufficient data for a new block header at offset ${offset}. Remaining: ${fileBuffer.length - offset} bytes.`,
      );
      break;
    }

    let genericBlockContainer: ParsedPcapNgGenericBlock;
    try {
      // Now use the determined/current byte order for parsing generic blocks
      genericBlockContainer = parsePcapNgGenericBlock(
        fileBuffer,
        offset,
        state.currentByteOrderIsBigEndian,
      );
    } catch (error: unknown) {
      const advanceBytes = 4; // Attempt to advance by alignment unit
      let errorMessage = 'Unknown error';
      if (error instanceof Error) {
        errorMessage = error.message;
      }
      if (error instanceof BufferOutOfBoundsError || error instanceof PcapParsingError) {
        logger.warn(
          `Error parsing generic block header at offset ${offset}: ${errorMessage}. Attempting to skip ${advanceBytes} bytes.`,
        );
      } else {
        logger.warn(
          `Unexpected error parsing generic block header at offset ${offset}: ${errorMessage}. Attempting to skip ${advanceBytes} bytes.`,
        );
      }
      offset += advanceBytes;
      if (offset >= fileBuffer.length) {
        // Check if we've run out of buffer
        logger.warn(
          `Advanced past end of buffer while skipping corrupted generic block header at offset ${offset - advanceBytes}. Stopping iteration.`,
        );
        break;
      }
      continue; // Try to parse the next block
    }

    const currentBlockType = genericBlockContainer.header.block_type;
    const currentBlockTotalLength = genericBlockContainer.header.block_total_length;
    const blockBody = genericBlockContainer.body;

    if (currentBlockTotalLength === 0) {
      logger.error(
        `Invalid block_total_length 0 encountered at offset ${offset} for block type ${currentBlockType.toString(16)}. Stopping iteration.`,
      );
      break;
    }
    // Minimum size check is already in parsePcapNgGenericBlock
    // if (currentBlockTotalLength < 12) {
    //     logger.error(`Invalid block_total_length ${currentBlockTotalLength} (too small) at offset ${offset} for block type ${currentBlockType.toString(16)}. Stopping iteration.`);
    //     break;
    // }
    if (offset + currentBlockTotalLength > fileBuffer.length) {
      logger.warn(
        `Block at offset ${offset} with type ${currentBlockType.toString(16)} claims length ${currentBlockTotalLength}, which exceeds buffer length ${fileBuffer.length}. Truncated file?`,
      );
      break;
    }

    // Note: The `blockData` used in the original switch was the full block.
    // The specific parsers in `block-parsers.ts` expect only the *body* of the block.
    // `genericBlockContainer.body` is what should be passed to them.

    try {
      switch (currentBlockType) {
        case PcapNgBlockType.SectionHeader: {
          const shb = parseSectionHeaderBlock(blockBody, state.currentByteOrderIsBigEndian);
          // Determine byte order from the parsed SHB's magic number.
          // The parseSectionHeaderBlock initially used the state's currentByteOrderIsBigEndian,
          // but the definitive endianness for the section comes from the SHB's own magic number.
          if (shb.byte_order_magic === 0x1a2b3c4d) {
            // Big-endian magic
            state.currentByteOrderIsBigEndian = true;
          } else if (shb.byte_order_magic === 0x4d3c2b1a) {
            // Little-endian magic
            state.currentByteOrderIsBigEndian = false;
          } else {
            // This should not happen if parseSectionHeaderBlock worked correctly with the initial guess
            logger.warn(
              `SHB at offset ${offset} has unrecognized byte_order_magic: 0x${shb.byte_order_magic.toString(16)}. Retaining previous byte order. Subsequent blocks in this section may be misinterpreted.`,
            );
          }

          // Reset interfaces for a new section.
          state.interfaces.clear();
          logger.info(
            `Parsed SHB at offset ${offset}. Byte order: ${state.currentByteOrderIsBigEndian ? 'big-endian' : 'little-endian'}. Section length: ${shb.section_length}`,
          );
          break;
        }
        case PcapNgBlockType.InterfaceDescription: {
          const idb = parseInterfaceDescriptionBlock(blockBody, state.currentByteOrderIsBigEndian);
          const currentInterfaceId = state.interfaces.size; // Assigns sequential IDs (0, 1, 2...)
          state.interfaces.set(currentInterfaceId, idb);
          logger.info(
            `Parsed IDB at offset ${offset}. Assigned Interface ID: ${currentInterfaceId}, LinkType: ${idb.linktype}`,
          );
          break;
        }
        case PcapNgBlockType.EnhancedPacket: {
          const epb = parseEnhancedPacketBlock(blockBody, state.currentByteOrderIsBigEndian);
          const iface = state.interfaces.get(epb.interface_id);
          if (!iface) {
            logger.warn(
              `EPB at offset ${offset} references unknown Interface ID: ${epb.interface_id}. Skipping packet.`,
            );
            break;
          }
          yield {
            interface_id: epb.interface_id,
            interface_link_type: iface.linktype,
            timestamp: (BigInt(epb.timestamp_high) << 32n) | BigInt(epb.timestamp_low),
            capturedLength: epb.captured_len,
            originalLength: epb.original_len,
            packetData: epb.packet_data,
            interface_name: iface.options
              ?.find((opt) => opt.code === 2 /* if_name */)
              ?.value.toString(), // Example: extract if_name
            interface_description: iface.options
              ?.find((opt) => opt.code === 3 /* if_description */)
              ?.value.toString(), // Example: extract if_description
          };
          break;
        }
        case PcapNgBlockType.SimplePacket: {
          // Deprecated, but might appear
          // const spb = parseSimplePacketBlock(blockBody, state.currentByteOrderIsBigEndian); // Parser not available
          logger.warn(
            `Encountered SimplePacketBlock (0x${PcapNgBlockType.SimplePacket.toString(16)}) at offset ${offset}. Parser not implemented. Skipping.`,
          );
          // Simple Packet Block does not have an interface ID. It implicitly uses the first interface (ID 0).
          // const interfaceId = 0;
          // const iface = state.interfaces.get(interfaceId);
          // if (!iface) {
          //   logger.warn(`SPB at offset ${offset} requires Interface ID 0, but it's not defined. Skipping packet.`);
          //   break;
          // }
          // yield {
          //   interface_id: interfaceId,
          //   interface_link_type: iface.linktype,
          //   timestamp: 0n, // SPB does not provide a timestamp.
          //   capturedLength: spb.packet_data.length,
          //   originalLength: spb.original_len,
          //   packetData: spb.packet_data,
          //   interface_name: iface.options?.find(opt => opt.code === 2)?.value.toString(),
          //   interface_description: iface.options?.find(opt => opt.code === 3)?.value.toString(),
          // };
          break;
        }
        case PcapNgBlockType.NameResolution: {
          const nrb = parseNameResolutionBlock(blockBody, state.currentByteOrderIsBigEndian);
          logger.info(`Parsed NRB at offset ${offset}. Record count: ${nrb.records.length}`);
          // TODO: Store name resolution records if needed for packet interpretation
          break;
        }
        case PcapNgBlockType.InterfaceStatistics: {
          // const isb = parseInterfaceStatisticsBlock(blockBody, state.currentByteOrderIsBigEndian); // Parser not available
          logger.warn(
            `Encountered InterfaceStatisticsBlock (0x${PcapNgBlockType.InterfaceStatistics.toString(16)}) at offset ${offset}. Parser not implemented. Skipping.`,
          );
          // const iface = state.interfaces.get(isb.interface_id);
          // logger.info(`Parsed ISB at offset ${offset} for Interface ID: ${isb.interface_id}. Timestamp: ${ (BigInt(isb.timestamp_high) << 32n) | BigInt(isb.timestamp_low)}`);
          break;
        }
        // Other known block types that don't yield packets directly
        case PcapNgBlockType.ObsoletePacket: // Obsolete Packet Block
        case PcapNgBlockType.CustomCanBeCopied:
        case PcapNgBlockType.CustomDoNotCopy:
          // case PcapNgBlockType.DecryptionSecrets: // Not in PcapNgBlockType enum from file
          logger.info(
            `Encountered known non-packet block type 0x${currentBlockType.toString(16)} at offset ${offset}. Skipping.`,
          );
          break;
        default:
          logger.warn(
            `Unknown or unhandled block type: 0x${currentBlockType.toString(16)} at offset ${offset}. Skipping ${currentBlockTotalLength} bytes.`,
          );
          break;
      }
    } catch (error: unknown) {
      let errorMessage = 'Unknown error';
      if (error instanceof Error) {
        errorMessage = error.message;
      }
      if (error instanceof PcapParsingError || error instanceof BufferOutOfBoundsError) {
        logger.warn(
          `Error parsing specific block type 0x${currentBlockType.toString(16)} (total length ${currentBlockTotalLength}) at offset ${offset}: ${errorMessage}. Skipping block.`,
        );
      } else {
        logger.warn(
          `Unexpected error processing block type 0x${currentBlockType.toString(16)} (total length ${currentBlockTotalLength}) at offset ${offset}: ${errorMessage}. Skipping block.`,
        );
      }
    }

    offset += currentBlockTotalLength;
    // Padding is handled by block_total_length and generic parser.
  }

  if (offset < fileBuffer.length) {
    logger.warn(
      `Iteration stopped prematurely. Processed ${offset} of ${fileBuffer.length} bytes.`,
    );
  } else {
    logger.info('Finished PCAPng packet iteration.');
  }
}
