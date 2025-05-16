import { Decoder, DecoderOutputLayer } from '../decoder';
import { readUint8, readUint16BE } from '../../utils/byte-readers';
import { BufferOutOfBoundsError } from '../../errors';

/**
 * Interface for the decoded ICMPv6 layer data.
 */
export interface ICMPv6Layer {
  type: number;
  code: number;
  checksum: number;
  data: Buffer; // For type-specific data or payload
  // TODO: Potentially add specific fields for common types like Echo, Neighbor Solicitation/Advertisement
}

/**
 * ICMPv6 Decoder class.
 * Implements the Decoder interface for ICMPv6 packets.
 */
export class ICMPv6Decoder implements Decoder<ICMPv6Layer> {
  public readonly protocolName = 'ICMPv6';

  /**
   * Decodes an ICMPv6 packet.
   * @param buffer The buffer containing the ICMPv6 packet data.
   * @param context Optional context information that might be needed for decoding
   *                (e.g., information from a preceding layer, like IPv6 header for checksum).
   * @returns A DecodedPacketLayer object for the ICMPv6 layer.
   * @throws BufferOutOfBoundsError if the buffer is too small.
   */
  public decode(buffer: Buffer, _context?: unknown): DecoderOutputLayer<ICMPv6Layer> {
    const ICMPV6_MIN_HEADER_LENGTH = 4; // Type (1) + Code (1) + Checksum (2)
    if (buffer.length < ICMPV6_MIN_HEADER_LENGTH) {
      throw new BufferOutOfBoundsError(
        `Buffer too small for ICMPv6 header. Expected at least ${ICMPV6_MIN_HEADER_LENGTH} bytes, got ${buffer.length}.`,
      );
    }

    const type = readUint8(buffer, 0);
    const code = readUint8(buffer, 1);
    const checksum = readUint16BE(buffer, 2);
    const messageBody = buffer.subarray(ICMPV6_MIN_HEADER_LENGTH);

    // TODO: Implement checksum validation if context and IPv6 pseudo-header details are available.
    // The 'context' parameter could carry the IPv6 pseudo-header.
    // For now, skipping checksum validation.

    const decodedLayerData: ICMPv6Layer = {
      type,
      code,
      checksum,
      data: messageBody, // This is the ICMPv6 message body (type-specific data)
    };

    return {
      protocolName: this.protocolName,
      headerLength: ICMPV6_MIN_HEADER_LENGTH, // Length of the fixed ICMPv6 header part
      data: decodedLayerData, // The ICMPv6Layer object itself
      payload: Buffer.alloc(0), // Buffer remaining *after* this ICMPv6 message. Typically none.
    };
  }

  /**
   * Determines the next protocol type.
   * ICMPv6 is typically a final layer, so this returns null.
   * @param _layerData The decoded ICMPv6 layer data. (unused)
   * @param _context Optional context information. (unused)
   * @returns null, as ICMPv6 is usually the last protocol in the stack.
   */
  public nextProtocolType(_layerData: ICMPv6Layer, _context?: unknown): string | null {
    return null;
  }
}
