import { Decoder, DecoderOutputLayer } from '../decoder';
import { BufferOutOfBoundsError } from '../../errors';
import { readUint16BE, readUint8 } from '../../utils/byte-readers';
import { formatMacAddress } from '../../utils/mac-address-formatter';
import { formatIPv4 } from '../../utils/ip-formatters';

// ARP Protocol Constants
const ETHERNET_HARDWARE_TYPE = 1;
const IPV4_PROTOCOL_TYPE = 0x0800; // 2048
const MAC_ADDRESS_LENGTH = 6;
const IPV4_ADDRESS_LENGTH = 4;

/**
 * Represents the decoded ARP layer data.
 */
export interface ARPLayer {
  /** Hardware type (e.g., 1 for Ethernet). */
  hardwareType: number;
  /** Protocol type (e.g., 0x0800 for IPv4). */
  protocolType: number;
  /** Length of hardware address (e.g., 6 for MAC address). */
  hardwareAddressLength: number;
  /** Length of protocol address (e.g., 4 for IPv4 address). */
  protocolAddressLength: number;
  /** ARP operation code (e.g., 1 for request, 2 for reply). */
  opcode: number;
  /** Sender's hardware (MAC) address. */
  senderMac: string;
  /** Sender's protocol (IP) address. */
  senderIp: string;
  /** Target hardware (MAC) address. */
  targetMac: string;
  /** Target protocol (IP) address. */
  targetIp: string;
}

/**
 * Decodes ARP (Address Resolution Protocol) packets.
 * ARP is defined in RFC 826.
 */
export class ARPDecoder implements Decoder<ARPLayer> {
  public readonly protocolName = 'ARP';

  /**
   * Decodes an ARP packet from the provided buffer.
   *
   * @param buffer - The buffer containing the ARP packet data, starting at the ARP header.
   * @returns A {@link DecoderOutputLayer} object with the parsed ARP data.
   * @throws {BufferOutOfBoundsError} If the buffer is too small to contain a valid ARP packet.
   */
  public decode(buffer: Buffer): DecoderOutputLayer<ARPLayer> {
    // Hardware Type (2) + Protocol Type (2) + HW Addr Len (1) + Proto Addr Len (1) + Opcode (2)
    // = 8 bytes for the fixed part of the header.
    // Variable parts: Sender MAC, Sender IP, Target MAC, Target IP.
    const MIN_ARP_HEADER_SIZE = 8; // Initial fields before variable length addresses

    if (buffer.length < MIN_ARP_HEADER_SIZE) {
      throw new BufferOutOfBoundsError(
        `Buffer too small for ARP header. Expected at least ${MIN_ARP_HEADER_SIZE} bytes for fixed fields, got ${buffer.length}.`,
      );
    }

    let offset = 0;

    const hardwareType = readUint16BE(buffer, offset);
    offset += 2;

    const protocolType = readUint16BE(buffer, offset);
    offset += 2;

    const hardwareAddressLength = readUint8(buffer, offset);
    offset += 1;

    const protocolAddressLength = readUint8(buffer, offset);
    offset += 1;

    const opcode = readUint16BE(buffer, offset);
    offset += 2;

    const expectedTotalLength =
      MIN_ARP_HEADER_SIZE + 2 * hardwareAddressLength + 2 * protocolAddressLength;
    if (buffer.length < expectedTotalLength) {
      throw new BufferOutOfBoundsError(
        `Buffer too small for ARP packet. Expected ${expectedTotalLength} bytes based on hardware_addr_len=${hardwareAddressLength} and protocol_addr_len=${protocolAddressLength}, got ${buffer.length}. Current offset: ${offset}.`,
      );
    }
 
    let senderMac: string;
    const senderMacBuffer = buffer.subarray(offset, offset + hardwareAddressLength);
    if (
      hardwareType === ETHERNET_HARDWARE_TYPE &&
      hardwareAddressLength === MAC_ADDRESS_LENGTH
    ) {
      senderMac = formatMacAddress(senderMacBuffer);
    } else {
      senderMac = senderMacBuffer.toString('hex');
    }
    offset += hardwareAddressLength;

    const senderIpBuffer = buffer.subarray(offset, offset + protocolAddressLength);
    let senderIp: string;
    if (
      protocolType === IPV4_PROTOCOL_TYPE &&
      protocolAddressLength === IPV4_ADDRESS_LENGTH
    ) {
      senderIp = formatIPv4(senderIpBuffer);
    } else {
      senderIp = senderIpBuffer.toString('hex'); // Fallback to hex
    }
    offset += protocolAddressLength;

    let targetMac: string;
    const targetMacBuffer = buffer.subarray(offset, offset + hardwareAddressLength);
    if (
      hardwareType === ETHERNET_HARDWARE_TYPE &&
      hardwareAddressLength === MAC_ADDRESS_LENGTH
    ) {
      targetMac = formatMacAddress(targetMacBuffer);
    } else {
      targetMac = targetMacBuffer.toString('hex');
    }
    offset += hardwareAddressLength;

    const targetIpBuffer = buffer.subarray(offset, offset + protocolAddressLength);
    let targetIp: string;
    if (
      protocolType === IPV4_PROTOCOL_TYPE &&
      protocolAddressLength === IPV4_ADDRESS_LENGTH
    ) {
      targetIp = formatIPv4(targetIpBuffer);
    } else {
      targetIp = targetIpBuffer.toString('hex'); // Fallback to hex
    }
    offset += protocolAddressLength;

    const data: ARPLayer = {
      hardwareType,
      protocolType,
      hardwareAddressLength,
      protocolAddressLength,
      opcode,
      senderMac,
      senderIp,
      targetMac,
      targetIp,
    };

    return {
      protocolName: this.protocolName,
      headerLength: offset,
      data,
      payload: buffer.subarray(offset), // ARP typically has no payload after these fields
    };
  }

  /**
   * Determines the next protocol type. For ARP, this is typically null as it's a final layer.
   *
   * @param _decodedLayer - The current decoded ARP layer data. Not used by this method for ARP.
   * @returns `null`, as ARP does not encapsulate another protocol in its payload.
   */
  public nextProtocolType(): string | number | null {
    return null;
  }
}
