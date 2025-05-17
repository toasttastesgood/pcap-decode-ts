import { Buffer } from 'buffer';
import { Decoder, DecoderOutputLayer } from '../decoder';
import { IPv4Layer } from './ipv4-layer';
import { readUint8, readUint16BE } from '../../utils/byte-readers'; // Removed readUInt32BE as it's not used
import { formatIPv4 } from '../../utils/ip-formatters';
import { BufferOutOfBoundsError, PcapDecodingError } from '../../errors';
import { logWarning } from '../../utils/logger'; // Corrected Logger import

const MIN_IPV4_HEADER_SIZE = 20; // Minimum IPv4 header size in bytes

/**
 * Decodes IPv4 (Internet Protocol version 4) packets.
 * This decoder parses the IPv4 header and extracts its fields.
 * It handles IPv4 options and payload truncation based on the `totalLength` field.
 */
export class IPv4Decoder implements Decoder<IPv4Layer> {
  /**
   * The human-readable name for this protocol.
   */
  public readonly protocolName = 'IPv4';
  private lastDecodedProtocol: number | undefined; // Used by nextProtocolType

  /**
   * Decodes an IPv4 packet from the provided buffer.
   *
   * @param buffer - The buffer containing the IPv4 packet, starting at the IPv4 header.
   * @param offset - The offset within the buffer where the IPv4 packet begins. Defaults to `0`.
   * @returns A {@link DecoderOutputLayer} object containing the parsed {@link IPv4Layer} data.
   * @throws {BufferOutOfBoundsError} If the buffer is too small for the IPv4 header or indicated total length.
   * @throws {PcapDecodingError} If malformed data is encountered (e.g., invalid version, negative payload length).
   */
  public decode(buffer: Buffer, offset: number = 0): DecoderOutputLayer<IPv4Layer> {
    if (buffer.length < offset + MIN_IPV4_HEADER_SIZE) {
      throw new BufferOutOfBoundsError(
        `Buffer too small for a minimal IPv4 header at offset ${offset}. Expected ${MIN_IPV4_HEADER_SIZE} bytes, got ${buffer.length - offset}.`,
      );
    }

    const firstByte = readUint8(buffer, offset); // Corrected function name
    const version = firstByte >> 4;
    const ihl = firstByte & 0x0f;

    if (version !== 4) {
      throw new PcapDecodingError(
        `Invalid IPv4 version at offset ${offset}: ${version}. Expected 4.`,
      );
    }

    // RFC 791: IHL is the length of the internet header in 32 bit words,
    // and thus points to the beginning of the data.
    // Minimum value for a correct header is 5 (i.e., 5 * 4 = 20 bytes).
    if (ihl < 5) {
      throw new PcapDecodingError(
        `Invalid IPv4 IHL at offset ${offset}: ${ihl}. Minimum value is 5 (for a 20-byte header).`,
      );
    }

    const headerLength = ihl * 4;
    if (buffer.length < offset + headerLength) {
      throw new BufferOutOfBoundsError(
        `Buffer too small for indicated IPv4 header length (${headerLength} bytes) at offset ${offset}. Buffer remaining: ${buffer.length - offset} bytes.`,
      );
    }

    const dscpEcnByte = readUint8(buffer, offset + 1); // Corrected function name
    const dscp = dscpEcnByte >> 2;
    const ecn = dscpEcnByte & 0x03;

    const totalLength = readUint16BE(buffer, offset + 2); // Corrected function name
    if (buffer.length < offset + totalLength) {
      // logWarning(`IPv4 TotalLength (${totalLength}) exceeds buffer remaining size (${buffer.length - offset}). Truncating.`);
      // This could be a warning, or an error depending on strictness.
      // For now, let's treat it as an error if the actual packet data is less than totalLength.
      // However, the PCAP might have truncated the packet.
      // The `payload` should be sliced based on `totalLength` relative to the start of the IP header.
    }

    const identification = readUint16BE(buffer, offset + 4); // Corrected function name

    const flagsFragmentOffset = readUint16BE(buffer, offset + 6); // Corrected function name
    const flags = flagsFragmentOffset >> 13;
    const fragmentOffset = flagsFragmentOffset & 0x1fff;

    const ttl = readUint8(buffer, offset + 8); // Corrected function name
    const protocol = readUint8(buffer, offset + 9); // Corrected function name
    this.lastDecodedProtocol = protocol;
    const headerChecksum = readUint16BE(buffer, offset + 10); // Corrected function name

    // Optional: Checksum validation
    // const calculatedChecksum = this.calculateChecksum(buffer.subarray(offset, offset + headerLength));
    // if (calculatedChecksum !== 0) { // Valid checksum should result in 0 when included in calculation
    //   logWarning(`IPv4 header checksum mismatch. Expected 0, got ${calculatedChecksum}. Packet Checksum: ${headerChecksum}`);
    // }

    const sourceIp = formatIPv4(buffer.subarray(offset + 12, offset + 16)); // Corrected function name
    const destinationIp = formatIPv4(buffer.subarray(offset + 16, offset + 20)); // Corrected function name

    let options: Buffer | undefined;
    if (ihl > 5) {
      const optionsLength = headerLength - MIN_IPV4_HEADER_SIZE;
      if (optionsLength > 0) {
        options = Buffer.from(
          buffer.subarray(offset + MIN_IPV4_HEADER_SIZE, offset + headerLength),
        );
      }
    }

    const payloadOffset = offset + headerLength;
    // The actual data length for this layer is totalLength.
    // The payload starts after the header and extends for (totalLength - headerLength) bytes.
    const payloadLength = totalLength - headerLength;

    if (payloadLength < 0) {
      throw new PcapDecodingError(
        `Calculated payload length is negative (${payloadLength}) at offset ${offset}. totalLength: ${totalLength}, headerLength: ${headerLength}`,
      );
    }

    // Ensure we don't read past the end of the provided buffer.
    // This can happen if totalLength reported in IP header is larger than the captured packet slice.
    const availableDataLength = buffer.length - payloadOffset;
    const actualPayloadLength = Math.min(payloadLength, availableDataLength);

    if (payloadLength > availableDataLength) {
      logWarning(
        `IPv4: totalLength (${totalLength}) implies payload of ${payloadLength} bytes, but only ${availableDataLength} bytes available in buffer after header. Payload will be truncated.`,
      );
    }

    const payload = Buffer.from(
      buffer.subarray(payloadOffset, payloadOffset + actualPayloadLength),
    );

    const decodedData: IPv4Layer = {
      version,
      ihl,
      dscp,
      ecn,
      totalLength,
      identification,
      flags,
      fragmentOffset,
      ttl,
      protocol,
      headerChecksum,
      sourceIp,
      destinationIp,
      options,
    };

    return {
      protocolName: this.protocolName,
      data: decodedData,
      headerLength: headerLength, // Corrected property name
      payload: payload,
    };
  }

  /**
   * Determines the protocol type of the next layer encapsulated within this IPv4 packet.
   * This is determined by the `protocol` field in the IPv4 header.
   *
   * @param decodedData - The decoded IPv4 layer data, containing the `protocol` field.
   * @returns The protocol number of the next layer (e.g., 6 for TCP, 17 for UDP), or `null` if not applicable.
   */
  public nextProtocolType(decodedData: IPv4Layer): number | string | null {
    return decodedData.protocol;
  }

  // Based on RFC 1071: https://tools.ietf.org/html/rfc1071
  // private calculateChecksum(headerBuffer: Buffer): number {
  //   let sum = 0;
  //   const length = headerBuffer.length;

  //   // Iterate over the header buffer in 16-bit words
  //   for (let i = 0; i < length; i += 2) {
  //     // If there's an odd byte at the end, it should be treated as if it were followed by a zero byte,
  //     // but IPv4 header length is always a multiple of 4 bytes (32 bits), so it's always even.
  //     sum += headerBuffer.readUInt16BE(i);
  //   }

  //   // Add carries
  //   while (sum >> 16) {
  //     sum = (sum & 0xffff) + (sum >> 16);
  //   }

  //   // One's complement
  //   return ~sum & 0xffff;
  // }
}
