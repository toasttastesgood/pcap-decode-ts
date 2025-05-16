import { Decoder, DecoderOutputLayer } from '../decoder';
import { readUint16BE } from '../../utils/byte-readers';
import { BufferOutOfBoundsError, PcapDecodingError } from '../../errors';

/**
 * Interface for the decoded UDP layer data.
 */
export interface UDPLayer {
  /** Source port number. */
  sourcePort: number;
  /** Destination port number. */
  destinationPort: number;
  /** Length of the UDP header and UDP data in octets. */
  length: number;
  /** Checksum for the UDP header and data (optional, may be zero). */
  checksum: number;
}

/**
 * UDP Decoder class.
 */
export class UDPDecoder implements Decoder<UDPLayer> {
  public readonly protocolName = 'UDP';

  /**
   * Decodes a UDP packet.
   * @param buffer - The buffer containing the UDP packet.
   * @param context - The decoder context, potentially containing IP header information for checksum.
   * @returns The decoded UDP layer.
   * @throws BufferOutOfBoundsError if the buffer is too small.
   */
  public decode(buffer: Buffer, _context?: unknown): DecoderOutputLayer<UDPLayer> {
    const UDP_HEADER_SIZE = 8;
    if (buffer.length < UDP_HEADER_SIZE) {
      throw new BufferOutOfBoundsError(
        `Buffer too small for UDP header. Expected at least ${UDP_HEADER_SIZE} bytes, got ${buffer.length}.`,
      );
    }

    const sourcePort = readUint16BE(buffer, 0);
    const destinationPort = readUint16BE(buffer, 2);
    const length = readUint16BE(buffer, 4);
    const checksum = readUint16BE(buffer, 6);

    if (length < UDP_HEADER_SIZE) {
      // The length field in UDP header is the length of UDP header + UDP data.
      throw new PcapDecodingError(
        `Invalid UDP length field (${length}) at offset 4. Value is less than minimum UDP header size (${UDP_HEADER_SIZE}).`,
      );
    }
    if (buffer.length < length) {
      throw new BufferOutOfBoundsError(
        `Buffer too small for declared UDP packet length. Expected ${length} bytes (from UDP length field at offset 4), got ${buffer.length}.`,
      );
    }

    // Optional: Checksum validation would go here.
    // For now, we'll skip it as per the instructions (optional but recommended).
    // If implementing, you'd need context.ipHeader for the pseudo-header.

    const headerBytes = 8;
    const payload = buffer.subarray(headerBytes, length);

    return {
      protocolName: this.protocolName,
      headerLength: headerBytes,
      data: {
        sourcePort,
        destinationPort,
        length,
        checksum,
      },
      payload,
    };
  }

  /**
   * Determines the next protocol type.
   * For UDP, this is typically application data, so we return null.
   * The decoding pipeline will handle specific application layer decoders based on port numbers.
   * @param _data - The decoded UDP layer data.
   * @param _context - The decoder context.
   * @returns Null, as UDP is usually the final layer before application data.
   */
  public nextProtocolType(_data: UDPLayer, _context?: unknown): string | null {
    return null;
  }
}
