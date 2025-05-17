import { Buffer } from 'buffer';
import { PcapGlobalHeader } from './global-header';
import { parsePcapGlobalHeader } from './global-header-parser';
import { PcapPacketRecordHeader } from './packet-record-header';
import { parsePcapPacketRecord } from './packet-record-parser';
import { PcapError, PcapParsingError } from '../errors';
import { logWarning } from '../utils/logger';

/**
 * Represents a parsed PCAP packet, including its header and data.
 */
export interface PcapPacket {
  header: PcapPacketRecordHeader;
  packetData: Buffer;
}

/**
 * Asynchronously iterates over packets in a PCAP file buffer.
 *
 * @param pcapBuffer The buffer containing the PCAP file data.
 * @returns An async iterable iterator yielding PcapPacket objects.
 * @throws PcapError if the PCAP global header is malformed or data is too short.
 * @throws PcapParsingError if a packet record is malformed (though these are logged and skipped by default).
 */
export async function* iteratePcapPackets(pcapBuffer: Buffer): AsyncIterableIterator<PcapPacket> {
  if (pcapBuffer.length < 24) {
    throw new PcapError('PCAP data is too short to contain a global header.');
  }

  const globalHeader: PcapGlobalHeader = parsePcapGlobalHeader(pcapBuffer);
  // parsePcapGlobalHeader will throw an error if parsing fails (e.g., invalid magic number, buffer too small),
  // so no need to check for a null/undefined result here.
  const isBigEndian = globalHeader.magic_number === 0xa1b2c3d4;

  let offset = 24; // Size of the global header

  while (offset < pcapBuffer.length) {
    if (pcapBuffer.length - offset < 16) {
      if (pcapBuffer.length - offset > 0) {
        logWarning(
          `Truncated PCAP data at offset ${offset}: expected 16 bytes for packet header, got ${
            pcapBuffer.length - offset
          } bytes. Stopping iteration.`,
        );
      }
      break; // Clean end of file or truncated data
    }

    try {
      const parsedPacketRecord = parsePcapPacketRecord(pcapBuffer, isBigEndian, offset);
      const packetHeader: PcapPacketRecordHeader = parsedPacketRecord.header;

      // Calculate next offset before yielding to ensure we can skip if data is bad
      const nextOffset = offset + 16 + packetHeader.incl_len;

      if (packetHeader.incl_len === 0) {
        yield {
          header: packetHeader,
          packetData: Buffer.alloc(0),
        };
        offset = nextOffset - packetHeader.incl_len; // effectively offset += 16
        continue;
      }

      // The packet data is already validated for length within parsePcapPacketRecord
      // and included in parsedPacketRecord.data.
      const packetData = parsedPacketRecord.data;

      yield {
        header: packetHeader,
        packetData,
      };
      offset = nextOffset;
    } catch (error) {
      if (error instanceof PcapParsingError) {
        logWarning(`Skipping corrupted PCAP packet at offset ${offset}: ${error.message}`);
        // Attempt to find the next packet. This is speculative and might not work
        // if the corruption is severe. A more robust approach might involve
        // trying to resynchronize by looking for known patterns or simply stopping.
        // For now, we'll advance by a minimal amount (e.g., 1 byte) or attempt to guess next packet.
        // A simple recovery: if incl_len was parseable but data was not, we might try to skip based on that.
        // However, if header itself is corrupt, incl_len is unreliable.
        // Let's try to advance by at least 1 byte to avoid an infinite loop if the error is persistent.
        // A better strategy might be to look for the next potential packet header if possible,
        // or give up after a certain number of consecutive errors.
        // For this task, we'll just log and try to advance past the problematic header (16 bytes).
        // If incl_len was also bad, this might still lead to issues.
        // A truly robust skip would be complex.
        // Let's assume for now that if parsePcapPacketRecord fails, we can't trust incl_len.
        // We'll try to skip the 16-byte header and hope the next one is valid.
        // If the error was due to incl_len pointing beyond buffer, parsePcapPacketRecord would have thrown.
        // So, if we are here, the header itself might be malformed, or incl_len is valid but data is not fully there (though parsePcapPacketRecord checks this).

        // A simple strategy: advance by 16 (header size) and hope the next record is parseable.
        // This is risky if incl_len was huge and caused the error, as we might skip too much or too little.
        // Given parsePcapPacketRecord now throws BufferOutOfBoundsError for incl_len issues,
        // an error here is more likely a malformed header.
        const advanceBytes = 16; // Try skipping the current assumed header
        logWarning(`Attempting to advance ${advanceBytes} bytes to find next packet.`);
        offset += advanceBytes;
        continue;
      } else {
        // Re-throw unexpected errors
        throw error;
      }
    }
  }
}
