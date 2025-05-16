import { Decoder, DecoderOutputLayer } from '../decoder';
import { ICMPv4Layer } from './icmpv4-layer';
import { readUint8, readUint16BE } from '../../utils/byte-readers';
import { BufferOutOfBoundsError } from '../../errors';

/**
 * ICMPv4 Decoder
 *
 * Decodes ICMPv4 packets.
 */
export class ICMPv4Decoder implements Decoder<ICMPv4Layer> {
  public readonly protocolName = 'ICMPv4';

  /**
   * Decodes an ICMPv4 packet.
   *
   * @param buffer - The buffer containing the ICMPv4 packet.
   * @param context - Optional context information (e.g., IP header for checksum).
   * @returns The decoded ICMPv4 layer.
   * @throws BufferOutOfBoundsError if the buffer is too small.
   */
  public decode(buffer: Buffer, context?: unknown): DecoderOutputLayer<ICMPv4Layer> {
    if (buffer.length < 4) {
      throw new BufferOutOfBoundsError(
        `Buffer too small for ICMPv4 header. Expected at least 4 bytes, got ${buffer.length}.`,
      );
    }

    const type = readUint8(buffer, 0);
    const code = readUint8(buffer, 1);
    const checksum = readUint16BE(buffer, 2);
    const icmpData = buffer.subarray(4); // Renamed to avoid conflict with DecodedPacketLayer.data

    // TODO: Implement checksum validation if context and IP header are available.
    // For now, skipping checksum validation.

    const decodedLayerData: ICMPv4Layer = {
      type,
      code,
      checksum,
      data: icmpData,
    };

    return {
      protocolName: this.protocolName,
      headerLength: buffer.length, // The entire ICMP message is considered the "header" for this layer
      data: decodedLayerData,
      payload: Buffer.alloc(0), // ICMPv4 typically doesn't have a payload beyond its own data
      context,
    };
  }

  /**
   * Determines the next protocol type.
   * ICMPv4 is typically a final layer, so this returns null.
   *
   * @param _layerData - The decoded ICMPv4 layer data.
   * @returns null, as ICMPv4 is usually a terminal protocol.
   */
  public nextProtocolType(_layerData: ICMPv4Layer): string | null {
    return null;
  }
}
