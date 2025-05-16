import { Decoder, DecoderOutputLayer } from '../decoder';
import { IPv6Layer } from './ipv6-layer';
import { readUint8, readUint16BE, readUint32BE } from '../../utils/byte-readers';
import { formatIPv6 } from '../../utils/ip-formatters';
import { BufferOutOfBoundsError, PcapDecodingError } from '../../errors';

const IPV6_HEADER_LENGTH = 40;

/**
 * Decodes IPv6 (Internet Protocol version 6) packets.
 * This decoder parses the fixed IPv6 header and extracts its fields.
 * Note: This decoder does not currently parse IPv6 extension headers.
 */
export class IPv6Decoder implements Decoder<IPv6Layer> {
  /**
   * The human-readable name for this protocol.
   */
  public readonly protocolName = 'IPv6';
  private lastNextHeader: number | null = null; // Stores the Next Header field for nextProtocolType

  /**
   * Decodes an IPv6 packet from the provided buffer.
   *
   * @param buffer - The buffer containing the IPv6 packet, starting at the IPv6 header.
   * @param offset - The offset within the buffer where the IPv6 packet begins. Defaults to `0`.
   * @returns A {@link DecoderOutputLayer} object containing the parsed {@link IPv6Layer} data.
   * @throws {BufferOutOfBoundsError} If the buffer is too small for the IPv6 header or declared payload length.
   * @throws {PcapDecodingError} If malformed data is encountered (e.g., invalid version).
   */
  public decode(buffer: Buffer, offset = 0): DecoderOutputLayer<IPv6Layer> {
    if (buffer.length < offset + IPV6_HEADER_LENGTH) {
      throw new BufferOutOfBoundsError(
        `Buffer too small for IPv6 header at offset ${offset}. Expected ${IPV6_HEADER_LENGTH} bytes, got ${buffer.length - offset}.`,
      );
    }

    const firstWord = readUint32BE(buffer, offset);
    const version = (firstWord & 0xf0000000) >>> 28;

    if (version !== 6) {
      throw new PcapDecodingError(
        `Invalid IPv6 version at offset ${offset}: ${version}. Expected 6.`,
      );
    }

    const trafficClass = (firstWord & 0x0ff00000) >>> 20;
    const flowLabel = firstWord & 0x000fffff;

    const payloadLength = readUint16BE(buffer, offset + 4);
    const nextHeader = readUint8(buffer, offset + 6);
    const hopLimit = readUint8(buffer, offset + 7);

    if (buffer.length < offset + IPV6_HEADER_LENGTH + payloadLength) {
      throw new BufferOutOfBoundsError(
        `Buffer too small for declared IPv6 payload length (${payloadLength} bytes) at offset ${offset + IPV6_HEADER_LENGTH}. Buffer remaining: ${buffer.length - (offset + IPV6_HEADER_LENGTH)} bytes.`,
      );
    }

    const sourceIpBuffer = buffer.subarray(offset + 8, offset + 24);
    const destinationIpBuffer = buffer.subarray(offset + 24, offset + 40);

    const sourceIp = formatIPv6(sourceIpBuffer);
    const destinationIp = formatIPv6(destinationIpBuffer);

    this.lastNextHeader = nextHeader;

    const data: IPv6Layer = {
      version,
      trafficClass,
      flowLabel,
      payloadLength,
      nextHeader,
      hopLimit,
      sourceIp,
      destinationIp,
    };

    return {
      protocolName: this.protocolName,
      data,
      headerLength: IPV6_HEADER_LENGTH,
      payload: buffer.subarray(
        offset + IPV6_HEADER_LENGTH,
        offset + IPV6_HEADER_LENGTH + payloadLength,
      ),
    };
  }

  /**
   * Determines the protocol type of the next layer encapsulated within this IPv6 packet.
   * This is determined by the `nextHeader` field in the IPv6 header.
   *
   * @param _decodedLayer - The decoded IPv6 layer data. Not directly used as `nextHeader` is stored internally during decode.
   * @returns The protocol number of the next layer (e.g., 6 for TCP, 17 for UDP, 58 for ICMPv6), or `null` if not applicable.
   */
  public nextProtocolType(_decodedLayer: IPv6Layer): number | null {
    return this.lastNextHeader;
  }
}
