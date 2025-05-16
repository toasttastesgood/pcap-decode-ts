import { Buffer } from 'buffer';
import { Decoder, DecoderOutputLayer } from '../decoder';
import { BufferOutOfBoundsError } from '../../errors';
import { formatMacAddress } from '../../utils/mac-address-formatter';
import { readUint16BE } from '../../utils/byte-readers';

/**
 * Represents the decoded data for an Ethernet II layer.
 */
export interface Ethernet2Layer {
  /** Destination MAC address (e.g., "AA:BB:CC:DD:EE:FF"). */
  destinationMac: string;
  /** Source MAC address (e.g., "AA:BB:CC:DD:EE:FF"). */
  sourceMac: string;
  /** The EtherType value indicating the protocol of the payload. */
  etherType: number;
}

/**
 * Decodes Ethernet II frames.
 */
export class Ethernet2Decoder implements Decoder<Ethernet2Layer> {
  public readonly protocolName: string = 'Ethernet II';

  /**
   * Decodes an Ethernet II frame from the provided buffer.
   * @param buffer The buffer containing the Ethernet II frame.
   * @returns A DecodedPacketLayer object containing the parsed Ethernet II data,
   *          the number of bytes consumed, and the remaining payload.
   * @throws BufferOutOfBoundsError if the buffer is too small.
   */
  public decode(buffer: Buffer): DecoderOutputLayer<Ethernet2Layer> {
    const headerLength = 14; // Dst MAC (6) + Src MAC (6) + EtherType (2)
    if (buffer.length < headerLength) {
      throw new BufferOutOfBoundsError(
        `Buffer too small for Ethernet II header. Expected ${headerLength} bytes, got ${buffer.length}.`,
      );
    }

    const destinationMacBuffer = buffer.subarray(0, 6);
    const sourceMacBuffer = buffer.subarray(6, 12);
    const etherType = readUint16BE(buffer, 12);

    const destinationMac = formatMacAddress(destinationMacBuffer);
    const sourceMac = formatMacAddress(sourceMacBuffer);

    const data: Ethernet2Layer = {
      destinationMac,
      sourceMac,
      etherType,
    };

    return {
      protocolName: this.protocolName,
      headerLength,
      data,
      payload: buffer.subarray(headerLength),
    };
  }

  /**
   * Determines the protocol type of the next layer based on the EtherType.
   * @param decodedLayer The decoded Ethernet II layer data.
   * @returns The EtherType value.
   */
  public nextProtocolType(decodedLayer: Ethernet2Layer): number {
    return decodedLayer.etherType;
  }
}
