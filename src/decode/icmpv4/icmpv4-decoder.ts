import { Buffer } from 'buffer';
import { Decoder, DecoderOutputLayer } from '../decoder';
import {
  ICMPv4Layer,
  ICMPv4EchoData,
  ICMPv4DestinationUnreachableData,
  ICMPv4TimeExceededData,
  ICMPv4RedirectData,
  ICMPv4TimestampData,
  ICMPv4AddressMaskData,
  ICMPv4ParameterProblemData,
  ICMPv4RouterAdvertisementData,
  ICMPv4RouterAdvertisementEntry,
  ICMPv4RouterSolicitationData,
} from './icmpv4-layer';
import { readUint8, readUint16BE, readUint32BE, readInt32BE } from '../../utils/byte-readers';
import { BufferOutOfBoundsError, PcapDecodingError } from '../../errors';
import { formatIPv4 } from '../../utils/ip-formatters';

// ICMPv4 Types (RFC 792 and others)
const ICMP_TYPE_ECHO_REPLY = 0;
const ICMP_TYPE_DESTINATION_UNREACHABLE = 3;
const ICMP_TYPE_SOURCE_QUENCH = 4; // Obsolete
const ICMP_TYPE_REDIRECT = 5;
const ICMP_TYPE_ECHO_REQUEST = 8;
const ICMP_TYPE_ROUTER_ADVERTISEMENT = 9;
const ICMP_TYPE_ROUTER_SOLICITATION = 10;
const ICMP_TYPE_TIME_EXCEEDED = 11;
const ICMP_TYPE_PARAMETER_PROBLEM = 12;
const ICMP_TYPE_TIMESTAMP_REQUEST = 13;
const ICMP_TYPE_TIMESTAMP_REPLY = 14;
const ICMP_TYPE_ADDRESS_MASK_REQUEST = 17;
const ICMP_TYPE_ADDRESS_MASK_REPLY = 18;

// Min lengths for specific parts
const MIN_ICMP_HEADER = 4; // Type, Code, Checksum
const ECHO_HEADER_EXTRA = 4; // Identifier, Sequence Number
const TIMESTAMP_HEADER_EXTRA = 16; // Identifier, SequenceNo, Originate, Receive, Transmit
const ADDR_MASK_HEADER_EXTRA = 4; // Identifier, SequenceNo, Address Mask (actually 8 total for header, 4 for mask)
const REDIRECT_HEADER_EXTRA = 4; // Gateway Address
const DEST_UNREACH_TIME_EXCEED_UNUSED = 4; // Unused part for these types
const PARAMETER_PROBLEM_FIXED_HEADER_EXTRA = 1; // Pointer (1 byte), rest is original IP header
const ROUTER_SOLICITATION_HEADER_EXTRA = 4; // Reserved
const ROUTER_ADVERTISEMENT_MIN_HEADER_EXTRA = 4; // Num Addrs (1), Addr Entry Size (1), Lifetime (2)
const ROUTER_ADVERTISEMENT_ENTRY_LENGTH = 8; // Router Address (4), Preference Level (4)
const IP_HEADER_MIN_LENGTH = 20; // For parsing original IP header

/**
 * Calculates the ICMPv4 checksum.
 * @param buffer The buffer containing the ICMP message (with checksum field potentially non-zero).
 * @returns The calculated checksum.
 */
function calculateICMPv4Checksum(buffer: Buffer): number {
  let sum = 0;
  const tempBuffer = Buffer.from(buffer);
  // Zero out the checksum field for calculation
  tempBuffer.writeUInt16BE(0, 2);

  for (let i = 0; i < tempBuffer.length; i += 2) {
    if (i + 1 < tempBuffer.length) {
      sum += tempBuffer.readUInt16BE(i);
    } else {
      sum += tempBuffer.readUInt8(i) << 8; // Pad with zero if odd length
    }
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  return ~sum & 0xffff;
}


/**
 * ICMPv4 Decoder
 * Decodes ICMPv4 packets, including type-specific fields for common messages.
 */
export class ICMPv4Decoder implements Decoder<ICMPv4Layer> {
  public readonly protocolName = 'ICMPv4';

  private getMessageType(type: number, code: number): string {
    switch (type) {
      case ICMP_TYPE_ECHO_REPLY: return 'Echo Reply';
      case ICMP_TYPE_DESTINATION_UNREACHABLE:
        switch (code) {
          case 0: return 'Destination Unreachable: Net Unreachable';
          case 1: return 'Destination Unreachable: Host Unreachable';
          case 2: return 'Destination Unreachable: Protocol Unreachable';
          case 3: return 'Destination Unreachable: Port Unreachable';
          case 4: return 'Destination Unreachable: Fragmentation Needed and DF set';
          case 5: return 'Destination Unreachable: Source Route Failed';
          case 6: return 'Destination Unreachable: Destination Network Unknown';
          case 7: return 'Destination Unreachable: Destination Host Unknown';
          // ... other codes
          default: return `Destination Unreachable: Code ${code}`;
        }
      case ICMP_TYPE_SOURCE_QUENCH: return 'Source Quench (Obsolete)';
      case ICMP_TYPE_REDIRECT:
        switch (code) {
          case 0: return 'Redirect: Redirect Datagrams for the Network';
          case 1: return 'Redirect: Redirect Datagrams for the Host';
          case 2: return 'Redirect: Redirect Datagrams for the Type of Service and Network';
          case 3: return 'Redirect: Redirect Datagrams for the Type of Service and Host';
          default: return `Redirect: Code ${code}`;
        }
      case ICMP_TYPE_ECHO_REQUEST: return 'Echo Request';
      case ICMP_TYPE_ROUTER_ADVERTISEMENT: return 'Router Advertisement';
      case ICMP_TYPE_ROUTER_SOLICITATION: return 'Router Solicitation';
      case ICMP_TYPE_TIME_EXCEEDED:
        switch (code) {
          case 0: return 'Time Exceeded: Time to Live exceeded in Transit';
          case 1: return 'Time Exceeded: Fragment Reassembly Time Exceeded';
          default: return `Time Exceeded: Code ${code}`;
        }
      case ICMP_TYPE_PARAMETER_PROBLEM: return `Parameter Problem: Code ${code}`;
      case ICMP_TYPE_TIMESTAMP_REQUEST: return 'Timestamp Request';
      case ICMP_TYPE_TIMESTAMP_REPLY: return 'Timestamp Reply';
      case ICMP_TYPE_ADDRESS_MASK_REQUEST: return 'Address Mask Request';
      case ICMP_TYPE_ADDRESS_MASK_REPLY: return 'Address Mask Reply';
      default: return `Unknown ICMPv4 Type: ${type}`;
    }
  }

  private parseOriginalIpDatagram(buffer: Buffer, offset: number): { originalIpHeader: Buffer, originalData: Buffer } {
    let originalIpHeader = Buffer.alloc(0);
    let originalData = Buffer.alloc(0);

    if (buffer.length > offset) {
      const potentialIpPayload = buffer.subarray(offset);
      if (potentialIpPayload.length > 0) {
        // Check for minimum IP header length before trying to read IHL
        if (potentialIpPayload.length >= 1) { // Need at least 1 byte for IHL
            const ihl = (readUint8(potentialIpPayload, 0) & 0x0F) * 4;
            if (ihl >= IP_HEADER_MIN_LENGTH && potentialIpPayload.length >= ihl) {
                originalIpHeader = Buffer.from(potentialIpPayload.subarray(0, ihl));
                if (potentialIpPayload.length > ihl) {
                    // RFC 792: "Internet Header + 64 bits of Data Datagram"
                    originalData = Buffer.from(potentialIpPayload.subarray(ihl, Math.min(ihl + 8, potentialIpPayload.length)));
                }
            } else {
                // Cannot reliably parse IHL, or not enough data for it.
                // Treat the rest as original IP header (might be partial or include data).
                originalIpHeader = Buffer.from(potentialIpPayload);
            }
        } else {
             // Not enough data to even attempt to read IHL. Treat what's left as header.
             originalIpHeader = Buffer.from(potentialIpPayload);
        }
      }
    }
    return { originalIpHeader, originalData };
  }

  public decode(buffer: Buffer, context?: unknown): DecoderOutputLayer<ICMPv4Layer> {
    if (buffer.length < MIN_ICMP_HEADER) {
      throw new BufferOutOfBoundsError(
        `Buffer too small for ICMPv4 base header. Expected at least ${MIN_ICMP_HEADER} bytes, got ${buffer.length}.`,
      );
    }

    const type = readUint8(buffer, 0);
    const code = readUint8(buffer, 1);
    const receivedChecksum = readUint16BE(buffer, 2);
    const calculatedChecksum = calculateICMPv4Checksum(buffer);

    if (receivedChecksum !== calculatedChecksum) {
      // Optionally, allow a flag to skip checksum validation for testing or specific scenarios
      // For now, we'll throw an error.
      throw new PcapDecodingError(`Invalid ICMPv4 checksum. Expected ${calculatedChecksum}, got ${receivedChecksum}.`);
    }

    const message = this.getMessageType(type, code);

    let parsedData: ICMPv4Layer['data'] = Buffer.from(buffer.subarray(MIN_ICMP_HEADER)); // Default to rest of buffer
    let specificHeaderLength = MIN_ICMP_HEADER; // Base ICMP header

    try {
      switch (type) {
        case ICMP_TYPE_ECHO_REQUEST:
        case ICMP_TYPE_ECHO_REPLY:
          if (buffer.length < MIN_ICMP_HEADER + ECHO_HEADER_EXTRA) {
            throw new BufferOutOfBoundsError(`Buffer too small for ICMP Echo/Reply. Expected ${MIN_ICMP_HEADER + ECHO_HEADER_EXTRA}, got ${buffer.length}.`);
          }
          specificHeaderLength = MIN_ICMP_HEADER + ECHO_HEADER_EXTRA;
          parsedData = {
            identifier: readUint16BE(buffer, 4),
            sequenceNumber: readUint16BE(buffer, 6),
            echoData: Buffer.from(buffer.subarray(specificHeaderLength)),
          } as ICMPv4EchoData;
          break;

        case ICMP_TYPE_DESTINATION_UNREACHABLE:
          if (buffer.length < MIN_ICMP_HEADER + DEST_UNREACH_TIME_EXCEED_UNUSED) {
            throw new BufferOutOfBoundsError(`Buffer too small for ICMP Destination Unreachable fixed part. Expected ${MIN_ICMP_HEADER + DEST_UNREACH_TIME_EXCEED_UNUSED}, got ${buffer.length}.`);
          }
          specificHeaderLength = MIN_ICMP_HEADER + DEST_UNREACH_TIME_EXCEED_UNUSED;
          const { originalIpHeader: duOrigIp, originalData: duOrigData } = this.parseOriginalIpDatagram(buffer, specificHeaderLength);
          const duData: ICMPv4DestinationUnreachableData = {
            originalIpHeader: duOrigIp,
            originalData: duOrigData,
          };
          if (code === 4) { // Fragmentation needed
            duData.nextHopMtu = readUint16BE(buffer, 6); // Bytes 6-7 are Next-Hop MTU
          } else {
            duData.unused = Buffer.from(buffer.subarray(4, MIN_ICMP_HEADER + DEST_UNREACH_TIME_EXCEED_UNUSED));
          }
          parsedData = duData;
          break;

        case ICMP_TYPE_TIME_EXCEEDED:
          if (buffer.length < MIN_ICMP_HEADER + DEST_UNREACH_TIME_EXCEED_UNUSED) {
             throw new BufferOutOfBoundsError(`Buffer too small for ICMP Time Exceeded fixed part. Expected ${MIN_ICMP_HEADER + DEST_UNREACH_TIME_EXCEED_UNUSED}, got ${buffer.length}.`);
          }
          specificHeaderLength = MIN_ICMP_HEADER + DEST_UNREACH_TIME_EXCEED_UNUSED;
          const { originalIpHeader: teOrigIp, originalData: teOrigData } = this.parseOriginalIpDatagram(buffer, specificHeaderLength);
          parsedData = {
            unused: Buffer.from(buffer.subarray(4, MIN_ICMP_HEADER + DEST_UNREACH_TIME_EXCEED_UNUSED)),
            originalIpHeader: teOrigIp,
            originalData: teOrigData,
          } as ICMPv4TimeExceededData;
          break;

        case ICMP_TYPE_PARAMETER_PROBLEM:
          // RFC 792: Pointer (1 byte), then 3 unused bytes, then IP header + 64 bits data
          if (buffer.length < MIN_ICMP_HEADER + PARAMETER_PROBLEM_FIXED_HEADER_EXTRA) {
            throw new BufferOutOfBoundsError(`Buffer too small for ICMP Parameter Problem fixed part. Expected ${MIN_ICMP_HEADER + PARAMETER_PROBLEM_FIXED_HEADER_EXTRA}, got ${buffer.length}.`);
          }
          specificHeaderLength = MIN_ICMP_HEADER + PARAMETER_PROBLEM_FIXED_HEADER_EXTRA;
          const pointer = readUint8(buffer, 4);
          // Bytes 5,6,7 are unused or for specific error codes (e.g. RFC 1122 for code 1)
          const unusedOrSpecific = Buffer.from(buffer.subarray(5, MIN_ICMP_HEADER + PARAMETER_PROBLEM_FIXED_HEADER_EXTRA));
          const { originalIpHeader: ppOrigIp, originalData: ppOrigData } = this.parseOriginalIpDatagram(buffer, specificHeaderLength);
          parsedData = {
            pointer,
            unusedOrSpecific,
            originalIpHeader: ppOrigIp,
            originalData: ppOrigData,
          } as ICMPv4ParameterProblemData;
          break;

        case ICMP_TYPE_SOURCE_QUENCH: // Obsolete, but structure is similar to others
           if (buffer.length < MIN_ICMP_HEADER + DEST_UNREACH_TIME_EXCEED_UNUSED) { // Uses same 4-byte "unused" field
             throw new BufferOutOfBoundsError(`Buffer too small for ICMP Source Quench. Expected ${MIN_ICMP_HEADER + DEST_UNREACH_TIME_EXCEED_UNUSED}, got ${buffer.length}.`);
           }
          specificHeaderLength = MIN_ICMP_HEADER + DEST_UNREACH_TIME_EXCEED_UNUSED;
          const { originalIpHeader: sqOrigIp, originalData: sqOrigData } = this.parseOriginalIpDatagram(buffer, specificHeaderLength);
          // Source Quench doesn't have a specific data structure in icmpv4-layer.ts beyond original IP.
          // We can represent its "data" part as the original IP header and data.
          // For now, we'll treat it as generic if no specific structure is defined,
          // or create a simple one if needed. The current fallback is Buffer.
          // Let's make it return the parsed original IP header and data for consistency.
           parsedData = {
             // unused: Buffer.from(buffer.subarray(4, MIN_ICMP_HEADER + DEST_UNREACH_TIME_EXCEED_UNUSED)), // if we define a specific type
             originalIpHeader: sqOrigIp,
             originalData: sqOrigData,
           }; // This would need a new type e.g. ICMPv4SourceQuenchData
           // For now, let it fall to default or handle as Buffer if no specific type is made.
           // Reverting to default behavior for now as SourceQuenchData is not defined.
           parsedData = Buffer.from(buffer.subarray(MIN_ICMP_HEADER));
          break;

        case ICMP_TYPE_REDIRECT:
          if (buffer.length < MIN_ICMP_HEADER + REDIRECT_HEADER_EXTRA) {
             throw new BufferOutOfBoundsError(`Buffer too small for ICMP Redirect. Expected ${MIN_ICMP_HEADER + REDIRECT_HEADER_EXTRA}, got ${buffer.length}.`);
          }
          specificHeaderLength = MIN_ICMP_HEADER + REDIRECT_HEADER_EXTRA; // Gateway address
          const gatewayAddress = formatIPv4(Buffer.from(buffer.subarray(4, 8)));
          const { originalIpHeader: redirOrigIp, originalData: redirOrigData } = this.parseOriginalIpDatagram(buffer, specificHeaderLength);
          parsedData = {
            gatewayAddress,
            originalIpHeader: redirOrigIp,
            originalData: redirOrigData,
          } as ICMPv4RedirectData;
          break;

        case ICMP_TYPE_TIMESTAMP_REQUEST:
        case ICMP_TYPE_TIMESTAMP_REPLY:
          if (buffer.length < MIN_ICMP_HEADER + TIMESTAMP_HEADER_EXTRA) {
            throw new BufferOutOfBoundsError(`Buffer too small for ICMP Timestamp. Expected ${MIN_ICMP_HEADER + TIMESTAMP_HEADER_EXTRA}, got ${buffer.length}.`);
          }
          specificHeaderLength = MIN_ICMP_HEADER + TIMESTAMP_HEADER_EXTRA;
          parsedData = {
            identifier: readUint16BE(buffer, 4),
            sequenceNumber: readUint16BE(buffer, 6),
            originateTimestamp: readUint32BE(buffer, 8),
            receiveTimestamp: readUint32BE(buffer, 12),
            transmitTimestamp: readUint32BE(buffer, 16),
          } as ICMPv4TimestampData;
          break;

        case ICMP_TYPE_ADDRESS_MASK_REQUEST:
        case ICMP_TYPE_ADDRESS_MASK_REPLY:
          // RFC 950: Identifier (2), Sequence (2), Address Mask (4)
          // Total 8 bytes after type/code/checksum for these fields.
          // So, header is 4 (base) + 8 = 12 bytes.
          if (buffer.length < MIN_ICMP_HEADER + ECHO_HEADER_EXTRA + 4 /* mask */) {
            throw new BufferOutOfBoundsError(`Buffer too small for ICMP Address Mask. Expected ${MIN_ICMP_HEADER + ECHO_HEADER_EXTRA + 4}, got ${buffer.length}.`);
          }
          specificHeaderLength = MIN_ICMP_HEADER + ECHO_HEADER_EXTRA + 4;
          parsedData = {
            identifier: readUint16BE(buffer, 4),
            sequenceNumber: readUint16BE(buffer, 6),
            addressMask: formatIPv4(Buffer.from(buffer.subarray(8, 12))),
          } as ICMPv4AddressMaskData;
          break;

        case ICMP_TYPE_ROUTER_SOLICITATION:
          if (buffer.length < MIN_ICMP_HEADER + ROUTER_SOLICITATION_HEADER_EXTRA) {
            throw new BufferOutOfBoundsError(`Buffer too small for ICMP Router Solicitation. Expected ${MIN_ICMP_HEADER + ROUTER_SOLICITATION_HEADER_EXTRA}, got ${buffer.length}.`);
          }
          specificHeaderLength = MIN_ICMP_HEADER + ROUTER_SOLICITATION_HEADER_EXTRA;
          parsedData = {
            reserved: Buffer.from(buffer.subarray(4, specificHeaderLength)),
          } as ICMPv4RouterSolicitationData;
          break;

        case ICMP_TYPE_ROUTER_ADVERTISEMENT:
          // RFC 1256: Num Addrs (1), Addr Entry Size (1, usually 2), Lifetime (2)
          // Each entry: Router Address (4), Preference Level (4)
          if (buffer.length < MIN_ICMP_HEADER + ROUTER_ADVERTISEMENT_MIN_HEADER_EXTRA) {
            throw new BufferOutOfBoundsError(`Buffer too small for ICMP Router Advertisement base. Expected ${MIN_ICMP_HEADER + ROUTER_ADVERTISEMENT_MIN_HEADER_EXTRA}, got ${buffer.length}.`);
          }
          const numAddrs = readUint8(buffer, 4);
          const addrEntrySize = readUint8(buffer, 5); // In 32-bit words, should be 2.
          const lifetime = readUint16BE(buffer, 6);

          if (addrEntrySize !== 2) {
            throw new PcapDecodingError(`Invalid address entry size in Router Advertisement: ${addrEntrySize}. Expected 2.`);
          }

          const expectedDataLength = numAddrs * ROUTER_ADVERTISEMENT_ENTRY_LENGTH;
          specificHeaderLength = MIN_ICMP_HEADER + ROUTER_ADVERTISEMENT_MIN_HEADER_EXTRA + expectedDataLength;

          if (buffer.length < specificHeaderLength) {
            throw new BufferOutOfBoundsError(`Buffer too small for ICMP Router Advertisement entries. Expected ${specificHeaderLength}, got ${buffer.length}.`);
          }

          const addresses: ICMPv4RouterAdvertisementEntry[] = [];
          let currentOffset = MIN_ICMP_HEADER + ROUTER_ADVERTISEMENT_MIN_HEADER_EXTRA;
          for (let i = 0; i < numAddrs; i++) {
            const routerAddress = formatIPv4(Buffer.from(buffer.subarray(currentOffset, currentOffset + 4)));
            const preferenceLevel = readInt32BE(buffer, currentOffset + 4); // Signed 32-bit
            addresses.push({ routerAddress, preferenceLevel });
            currentOffset += ROUTER_ADVERTISEMENT_ENTRY_LENGTH;
          }
          parsedData = {
            numAddrs,
            addrEntrySize,
            lifetime,
            addresses,
          } as ICMPv4RouterAdvertisementData;
          break;

        default:
          // For unknown types, data is the rest of the buffer after base header
          parsedData = Buffer.from(buffer.subarray(MIN_ICMP_HEADER));
          specificHeaderLength = MIN_ICMP_HEADER;
          break;
      }
    } catch (e) {
      if (e instanceof BufferOutOfBoundsError || e instanceof PcapDecodingError) {
        // Re-throw known decoding errors
        throw e;
      }
      // For other unexpected errors during specific parsing, wrap them.
      // Fallback to generic data and log/throw a PcapDecodingError.
      // This indicates a potential issue in the decoder logic itself for a known type.
      // For now, we'll create a PcapDecodingError and include the original error.
      // The `parsedData` will remain the default (rest of buffer).
      throw new PcapDecodingError(`Unexpected error parsing ICMPv4 type ${type}, code ${code}: ${(e as Error).message}. Original error: ${String(e)}`);
    }


    const decodedLayer: ICMPv4Layer = {
      type,
      code,
      checksum: receivedChecksum,
      message,
      data: parsedData,
      validChecksum: receivedChecksum === calculatedChecksum, // Add checksum validity info
    };

    return {
      protocolName: this.protocolName,
      headerLength: buffer.length, // The entire ICMP message is considered the "header" for this layer
      data: decodedLayer,
      payload: Buffer.alloc(0), // ICMP's "payload" is encapsulated within its `data` field
      context,
    };
  }

  public nextProtocolType(_layerData: ICMPv4Layer): string | null {
    return null;
  }
}
