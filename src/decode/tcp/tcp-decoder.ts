import { Decoder, DecoderOutputLayer } from '../decoder';
import { TCPLayer } from './tcp-layer';
import { readUint16BE, readUint32BE } from '../../utils/byte-readers';
import { BufferOutOfBoundsError, PcapDecodingError } from '../../errors';

/**
 * Decodes TCP (Transmission Control Protocol) packets.
 */
export class TCPDecoder implements Decoder<TCPLayer> {
  public readonly protocolName = 'TCP';

  /**
   * Decodes a TCP packet.
   * @param buffer The buffer containing the TCP packet data.
   * @param context Contextual information, potentially including IP header details for checksum.
   * @returns The decoded TCP layer.
   * @throws BufferOutOfBoundsError if the buffer is too small.
   */
  public decode(buffer: Buffer, _context?: unknown): DecoderOutputLayer<TCPLayer> {
    const MIN_TCP_HEADER_SIZE = 20;
    if (buffer.length < MIN_TCP_HEADER_SIZE) {
      throw new BufferOutOfBoundsError(
        `Buffer too small for TCP header. Expected at least ${MIN_TCP_HEADER_SIZE} bytes, got ${buffer.length}.`,
      );
    }

    const sourcePort = readUint16BE(buffer, 0);
    const destinationPort = readUint16BE(buffer, 2);
    const sequenceNumber = readUint32BE(buffer, 4);
    const acknowledgmentNumber = readUint32BE(buffer, 8);

    const dataOffsetReservedFlags = readUint16BE(buffer, 12);
    const dataOffset = (dataOffsetReservedFlags & 0xf000) >> 12; // First 4 bits
    const reserved = (dataOffsetReservedFlags & 0x0e00) >> 9; // Next 3 bits (masking out NS)
    // Note: The NS flag (bit 4 of reserved field, or bit 0 of the 12 bits) is included in flags.ns
    const flagsByte = dataOffsetReservedFlags & 0x01ff; // Last 9 bits for flags

    const flags = {
      ns: (flagsByte & 0x0100) !== 0, // Bit 0 (from the 9 flag bits, or bit 8 of the 16-bit field if counting from right)
      cwr: (flagsByte & 0x0080) !== 0, // Bit 1
      ece: (flagsByte & 0x0040) !== 0, // Bit 2
      urg: (flagsByte & 0x0020) !== 0, // Bit 3
      ack: (flagsByte & 0x0010) !== 0, // Bit 4
      psh: (flagsByte & 0x0008) !== 0, // Bit 5
      rst: (flagsByte & 0x0004) !== 0, // Bit 6
      syn: (flagsByte & 0x0002) !== 0, // Bit 7
      fin: (flagsByte & 0x0001) !== 0, // Bit 8
    };

    const windowSize = readUint16BE(buffer, 14);
    const checksum = readUint16BE(buffer, 16);
    const urgentPointer = readUint16BE(buffer, 18);

    const headerLength = dataOffset * 4;
    if (headerLength < MIN_TCP_HEADER_SIZE) {
      // Data offset can be less than 5, which is invalid.
      throw new PcapDecodingError(
        `Invalid TCP data offset ${dataOffset} at offset 12. Resulting header length ${headerLength} is less than minimum ${MIN_TCP_HEADER_SIZE}.`,
      );
    }
    if (buffer.length < headerLength) {
      throw new BufferOutOfBoundsError(
        `Buffer too small for declared TCP header length. Expected ${headerLength} bytes (data_offset*4), got ${buffer.length}.`,
      );
    }

    let options: Buffer | undefined = undefined;
    if (dataOffset > 5) {
      const optionsLength = headerLength - 20;
      if (optionsLength > 0) {
        options = buffer.subarray(20, headerLength);
      }
    }

    // TODO: Implement checksum validation if context.ipHeader is available.
    // const ipHeader = context?.ipHeader;
    // if (ipHeader) {
    //   // Calculate pseudo-header
    //   // Calculate TCP checksum
    //   // if (calculatedChecksum !== checksum) {
    //   //   console.warn('TCP checksum mismatch');
    //   // }
    // }

    const payload = buffer.subarray(headerLength);

    const decodedData: TCPLayer = {
      sourcePort,
      destinationPort,
      sequenceNumber,
      acknowledgmentNumber,
      dataOffset,
      reserved,
      flags,
      windowSize,
      checksum,
      urgentPointer,
      options,
    };

    return {
      protocolName: this.protocolName,
      headerLength: headerLength,
      data: decodedData,
      payload: payload,
    };
  }

  /**
   * Determines the next protocol type. For TCP, this is typically application data,
   * so we return null. The decoding pipeline will handle application-specific decoders.
   * @param _data The decoded TCP layer data.
   * @param _context Contextual information.
   * @returns Null, as TCP is usually the final layer before application data.
   */
  public nextProtocolType(_data: TCPLayer, _context?: unknown): string | null {
    return null;
  }
}
