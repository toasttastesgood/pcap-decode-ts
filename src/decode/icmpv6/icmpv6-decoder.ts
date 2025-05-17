import { Buffer } from 'buffer';
import { Decoder, DecoderOutputLayer } from '../decoder';
import {
  ICMPv6Layer,
  ICMPv6EchoData,
  ICMPv6DestinationUnreachableData,
  ICMPv6PacketTooBigData,
  ICMPv6TimeExceededData,
  ICMPv6ParameterProblemData,
  ICMPv6RouterSolicitationData,
  ICMPv6RouterAdvertisementData,
  ICMPv6NeighborSolicitationData,
  ICMPv6NeighborAdvertisementData,
  ICMPv6RedirectData,
  ICMPv6Option,
} from './icmpv6-layer'; // Import from the new layer file
import { readUint8, readUint16BE, readUint32BE } from '../../utils/byte-readers';
import { BufferOutOfBoundsError, PcapDecodingError } from '../../errors';
import { formatIPv6 } from '../../utils/ip-formatters';
import { formatMacAddress } from '../../utils/mac-address-formatter';


// ICMPv6 Types (RFC 4443, RFC 4861)
const ICMPV6_TYPE_DESTINATION_UNREACHABLE = 1;
const ICMPV6_TYPE_PACKET_TOO_BIG = 2;
const ICMPV6_TYPE_TIME_EXCEEDED = 3;
const ICMPV6_TYPE_PARAMETER_PROBLEM = 4;
const ICMPV6_TYPE_ECHO_REQUEST = 128;
const ICMPV6_TYPE_ECHO_REPLY = 129;
const ICMPV6_TYPE_ROUTER_SOLICITATION = 133;
const ICMPV6_TYPE_ROUTER_ADVERTISEMENT = 134;
const ICMPV6_TYPE_NEIGHBOR_SOLICITATION = 135;
const ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT = 136;
const ICMPV6_TYPE_REDIRECT_MESSAGE = 137;

// ICMPv6 Option Types (RFC 4861)
const ICMPV6_OPTION_TYPE_SOURCE_LLA = 1;
const ICMPV6_OPTION_TYPE_TARGET_LLA = 2;
const ICMPV6_OPTION_TYPE_PREFIX_INFO = 3;
const ICMPV6_OPTION_TYPE_REDIRECTED_HEADER = 4;
const ICMPV6_OPTION_TYPE_MTU = 5;

const ICMPV6_MIN_HEADER_LENGTH = 4; // Type (1) + Code (1) + Checksum (2)
const ICMPV6_ECHO_EXTRA_LENGTH = 4; // Identifier (2) + Sequence Number (2)
const ICMPV6_PACKET_TOO_BIG_MTU_LENGTH = 4; // MTU (4)
const ICMPV6_PARAM_PROBLEM_POINTER_LENGTH = 4; // Pointer (4)
const ICMPV6_ROUTER_SOL_RESERVED_LENGTH = 4;
const ICMPV6_ROUTER_ADV_FIXED_LENGTH = 12; // HopLimit(1)+Flags(1)+Lifetime(2)+Reachable(4)+Retrans(4)
const ICMPV6_NEIGHBOR_SOL_FIXED_LENGTH = 20; // Reserved(4) + TargetAddress(16)
const ICMPV6_NEIGHBOR_ADV_FIXED_LENGTH = 4; // Flags(1) + Reserved(3) before TargetAddress
const ICMPV6_NEIGHBOR_ADV_TARGET_ADDR_OFFSET = 4;
const ICMPV6_NEIGHBOR_ADV_OPTIONS_OFFSET = 20; // After Flags (4) and Target Address (16)
const ICMPV6_REDIRECT_FIXED_PART_LENGTH = 8; // Reserved(4) + TargetAddress(16) + DestAddress(16) = 36, but options start after Dest.
                                           // Reserved (4) is what's before Target Address.
const ICMPV6_REDIRECT_TARGET_ADDR_OFFSET = 4;
const ICMPV6_REDIRECT_DEST_ADDR_OFFSET = 20; // After Target Address
const ICMPV6_REDIRECT_OPTIONS_OFFSET = 36; // After Dest Address


export class ICMPv6Decoder implements Decoder<ICMPv6Layer> {
  public readonly protocolName = 'ICMPv6';

  private getMessageType(type: number, code: number): string {
    // Basic messages from RFC 4443
    if (type === ICMPV6_TYPE_DESTINATION_UNREACHABLE) {
      switch (code) {
        case 0: return 'Destination Unreachable: No route to destination';
        case 1: return 'Destination Unreachable: Communication with destination administratively prohibited';
        case 2: return 'Destination Unreachable: Beyond scope of source address';
        case 3: return 'Destination Unreachable: Address unreachable';
        case 4: return 'Destination Unreachable: Port unreachable';
        case 5: return 'Destination Unreachable: Source address failed ingress/egress policy';
        case 6: return 'Destination Unreachable: Reject route to destination';
        default: return `Destination Unreachable: Code ${code}`;
      }
    }
    if (type === ICMPV6_TYPE_PACKET_TOO_BIG) return 'Packet Too Big';
    if (type === ICMPV6_TYPE_TIME_EXCEEDED) {
      switch (code) {
        case 0: return 'Time Exceeded: Hop limit exceeded in transit';
        case 1: return 'Time Exceeded: Fragment reassembly time exceeded';
        default: return `Time Exceeded: Code ${code}`;
      }
    }
    if (type === ICMPV6_TYPE_PARAMETER_PROBLEM) {
      switch (code) {
        case 0: return 'Parameter Problem: Erroneous header field encountered';
        case 1: return 'Parameter Problem: Unrecognized Next Header type encountered';
        case 2: return 'Parameter Problem: Unrecognized IPv6 option encountered';
        default: return `Parameter Problem: Code ${code}`;
      }
    }
    if (type === ICMPV6_TYPE_ECHO_REQUEST) return 'Echo Request';
    if (type === ICMPV6_TYPE_ECHO_REPLY) return 'Echo Reply';

    // NDP Messages (RFC 4861)
    if (type === ICMPV6_TYPE_ROUTER_SOLICITATION) return 'Router Solicitation';
    if (type === ICMPV6_TYPE_ROUTER_ADVERTISEMENT) return 'Router Advertisement';
    if (type === ICMPV6_TYPE_NEIGHBOR_SOLICITATION) return 'Neighbor Solicitation';
    if (type === ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT) return 'Neighbor Advertisement';
    if (type === ICMPV6_TYPE_REDIRECT_MESSAGE) return 'Redirect Message';

    return `Unknown ICMPv6 Type: ${type}`;
  }

  private parseOptions(buffer: Buffer): ICMPv6Option[] {
    const options: ICMPv6Option[] = [];
    let offset = 0;
    while (offset < buffer.length) {
      if (offset + 2 > buffer.length) break;
      const type = readUint8(buffer, offset);
      const length = readUint8(buffer, offset + 1);
      
      if (length === 0) {
        throw new PcapDecodingError(`ICMPv6 option has invalid length 0 at offset ${offset}`);
      }
      const optionTotalBytes = length * 8;
      if (offset + optionTotalBytes > buffer.length) {
          throw new BufferOutOfBoundsError(`ICMPv6 option (type ${type}, length ${optionTotalBytes}) at offset ${offset} exceeds buffer bounds.`);
      }
      
      const optionDataBuffer = Buffer.from(buffer.subarray(offset + 2, offset + optionTotalBytes));
      const option: ICMPv6Option = { type, length, rawData: optionDataBuffer };

      // Specific option parsing
      if (optionDataBuffer.length >= (optionTotalBytes -2) ) { // Ensure data buffer has enough bytes for content
        switch (type) {
          case ICMPV6_OPTION_TYPE_SOURCE_LLA:
          case ICMPV6_OPTION_TYPE_TARGET_LLA:
            if (optionTotalBytes - 2 === 6 && optionDataBuffer.length >=6) { // LLA is 6 bytes after type/length
              option.linkLayerAddress = formatMacAddress(Buffer.from(optionDataBuffer.subarray(0, 6)));
            }
            break;
          case ICMPV6_OPTION_TYPE_PREFIX_INFO:
            if (optionTotalBytes - 2 === 30-2 && optionDataBuffer.length >= 28) { // 30 total, 28 for data part
              const flagsByte = readUint8(optionDataBuffer, 1); // PrefixLen is at 0, Flags at 1
              option.prefix = {
                prefixLength: readUint8(optionDataBuffer, 0),
                flags: { L: (flagsByte & 0x80) !== 0, A: (flagsByte & 0x40) !== 0 },
                validLifetime: readUint32BE(optionDataBuffer, 2),
                preferredLifetime: readUint32BE(optionDataBuffer, 6),
                // Reserved 4 bytes at optionDataBuffer[10-13]
                prefixAddress: formatIPv6(Buffer.from(optionDataBuffer.subarray(14, 14 + 16))),
              };
            }
            break;
          case ICMPV6_OPTION_TYPE_MTU:
            if (optionTotalBytes - 2 === 6 && optionDataBuffer.length >=6) { // Reserved (2) + MTU (4)
              option.mtu = readUint32BE(optionDataBuffer, 2);
            }
            break;
        }
      }
      options.push(option);
      offset += optionTotalBytes;
    }
    return options;
  }


  public decode(buffer: Buffer, _context?: unknown): DecoderOutputLayer<ICMPv6Layer> {
    if (buffer.length < ICMPV6_MIN_HEADER_LENGTH) {
      throw new BufferOutOfBoundsError(
        `Buffer too small for ICMPv6 header. Expected at least ${ICMPV6_MIN_HEADER_LENGTH} bytes, got ${buffer.length}.`,
      );
    }

    const type = readUint8(buffer, 0);
    const code = readUint8(buffer, 1);
    const checksum = readUint16BE(buffer, 2);
    const message = this.getMessageType(type, code);
    const messageBody = Buffer.from(buffer.subarray(ICMPV6_MIN_HEADER_LENGTH));
    let parsedData: ICMPv6Layer['data'] = messageBody; // Default

    // TODO: Checksum validation

    try {
      switch (type) {
        case ICMPV6_TYPE_ECHO_REQUEST:
        case ICMPV6_TYPE_ECHO_REPLY:
          if (messageBody.length < ICMPV6_ECHO_EXTRA_LENGTH) {
            throw new BufferOutOfBoundsError(`Buffer too small for ICMPv6 Echo/Reply body. Expected ${ICMPV6_ECHO_EXTRA_LENGTH}, got ${messageBody.length}.`);
          }
          parsedData = {
            identifier: readUint16BE(messageBody, 0),
            sequenceNumber: readUint16BE(messageBody, 2),
            echoData: Buffer.from(messageBody.subarray(ICMPV6_ECHO_EXTRA_LENGTH)),
          } as ICMPv6EchoData;
          break;

        case ICMPV6_TYPE_DESTINATION_UNREACHABLE:
          if (messageBody.length < 4) { // For unused field
             throw new BufferOutOfBoundsError(`Buffer too small for ICMPv6 Dest Unreachable unused field. Expected 4, got ${messageBody.length}.`);
          }
          parsedData = {
            unused: Buffer.from(messageBody.subarray(0, 4)),
            originalPacketData: Buffer.from(messageBody.subarray(4)),
          } as ICMPv6DestinationUnreachableData;
          break;

        case ICMPV6_TYPE_PACKET_TOO_BIG:
          if (messageBody.length < ICMPV6_PACKET_TOO_BIG_MTU_LENGTH) {
            throw new BufferOutOfBoundsError(`Buffer too small for ICMPv6 Packet Too Big MTU. Expected ${ICMPV6_PACKET_TOO_BIG_MTU_LENGTH}, got ${messageBody.length}.`);
          }
          parsedData = {
            mtu: readUint32BE(messageBody, 0),
            originalPacketData: Buffer.from(messageBody.subarray(ICMPV6_PACKET_TOO_BIG_MTU_LENGTH)),
          } as ICMPv6PacketTooBigData;
          break;

        case ICMPV6_TYPE_TIME_EXCEEDED:
           if (messageBody.length < 4) { // For unused field
             throw new BufferOutOfBoundsError(`Buffer too small for ICMPv6 Time Exceeded unused field. Expected 4, got ${messageBody.length}.`);
           }
          parsedData = {
            unused: Buffer.from(messageBody.subarray(0, 4)),
            originalPacketData: Buffer.from(messageBody.subarray(4)),
          } as ICMPv6TimeExceededData;
          break;

        case ICMPV6_TYPE_PARAMETER_PROBLEM:
          if (messageBody.length < ICMPV6_PARAM_PROBLEM_POINTER_LENGTH) {
            throw new BufferOutOfBoundsError(`Buffer too small for ICMPv6 Parameter Problem pointer. Expected ${ICMPV6_PARAM_PROBLEM_POINTER_LENGTH}, got ${messageBody.length}.`);
          }
          parsedData = {
            pointer: readUint32BE(messageBody, 0),
            originalPacketData: Buffer.from(messageBody.subarray(ICMPV6_PARAM_PROBLEM_POINTER_LENGTH)),
          } as ICMPv6ParameterProblemData;
          break;
        
        case ICMPV6_TYPE_ROUTER_SOLICITATION:
            if (messageBody.length < ICMPV6_ROUTER_SOL_RESERVED_LENGTH) {
                 throw new BufferOutOfBoundsError(`Buffer too small for ICMPv6 Router Solicitation reserved field. Expected ${ICMPV6_ROUTER_SOL_RESERVED_LENGTH}, got ${messageBody.length}.`);
            }
            parsedData = {
                reserved: Buffer.from(messageBody.subarray(0, ICMPV6_ROUTER_SOL_RESERVED_LENGTH)),
                options: this.parseOptions(Buffer.from(messageBody.subarray(ICMPV6_ROUTER_SOL_RESERVED_LENGTH))),
            } as ICMPv6RouterSolicitationData;
            break;

        case ICMPV6_TYPE_ROUTER_ADVERTISEMENT:
            if (messageBody.length < ICMPV6_ROUTER_ADV_FIXED_LENGTH) {
                throw new BufferOutOfBoundsError(`Buffer too small for ICMPv6 Router Advertisement fixed fields. Expected ${ICMPV6_ROUTER_ADV_FIXED_LENGTH}, got ${messageBody.length}.`);
            }
            const advFlags = readUint8(messageBody, 1);
            parsedData = {
                currentHopLimit: readUint8(messageBody, 0),
                flags: { M: (advFlags & 0x80) !== 0, O: (advFlags & 0x40) !== 0, H: (advFlags & 0x20) !==0 },
                routerLifetime: readUint16BE(messageBody, 2),
                reachableTime: readUint32BE(messageBody, 4),
                retransTimer: readUint32BE(messageBody, 8),
                options: this.parseOptions(Buffer.from(messageBody.subarray(ICMPV6_ROUTER_ADV_FIXED_LENGTH))),
            } as ICMPv6RouterAdvertisementData;
            break;

        case ICMPV6_TYPE_NEIGHBOR_SOLICITATION:
            if (messageBody.length < ICMPV6_NEIGHBOR_SOL_FIXED_LENGTH) { // Reserved (4) + TargetAddress (16)
                 throw new BufferOutOfBoundsError(`Buffer too small for ICMPv6 Neighbor Solicitation fixed fields. Expected ${ICMPV6_NEIGHBOR_SOL_FIXED_LENGTH}, got ${messageBody.length}.`);
            }
            parsedData = {
                reserved: Buffer.from(messageBody.subarray(0, 4)),
                targetAddress: formatIPv6(Buffer.from(messageBody.subarray(4, 20))),
                options: this.parseOptions(Buffer.from(messageBody.subarray(ICMPV6_NEIGHBOR_SOL_FIXED_LENGTH))),
            } as ICMPv6NeighborSolicitationData;
            break;
        
        case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT:
             // Flags (1 byte in RFC, but structure often shows 4 bytes with 3 reserved after flags) + Target Address (16)
            if (messageBody.length < ICMPV6_NEIGHBOR_ADV_TARGET_ADDR_OFFSET + 16) { // 4 for flags/reserved + 16 for target
                 throw new BufferOutOfBoundsError(`Buffer too small for ICMPv6 Neighbor Advertisement fixed fields. Expected ${ICMPV6_NEIGHBOR_ADV_TARGET_ADDR_OFFSET + 16}, got ${messageBody.length}.`);
            }
            const naFlagsByte = readUint8(messageBody, 0);
            parsedData = {
                flags: { R: (naFlagsByte & 0x80) !== 0, S: (naFlagsByte & 0x40) !== 0, O: (naFlagsByte & 0x20) !== 0 },
                targetAddress: formatIPv6(Buffer.from(messageBody.subarray(ICMPV6_NEIGHBOR_ADV_TARGET_ADDR_OFFSET, ICMPV6_NEIGHBOR_ADV_TARGET_ADDR_OFFSET + 16))),
                options: this.parseOptions(Buffer.from(messageBody.subarray(ICMPV6_NEIGHBOR_ADV_OPTIONS_OFFSET))),
            } as ICMPv6NeighborAdvertisementData;
            break;

        case ICMPV6_TYPE_REDIRECT_MESSAGE:
            if (messageBody.length < ICMPV6_REDIRECT_OPTIONS_OFFSET) { // Reserved(4) + Target(16) + Dest(16)
                 throw new BufferOutOfBoundsError(`Buffer too small for ICMPv6 Redirect fixed fields. Expected ${ICMPV6_REDIRECT_OPTIONS_OFFSET}, got ${messageBody.length}.`);
            }
            parsedData = {
                reserved: Buffer.from(messageBody.subarray(0, ICMPV6_REDIRECT_TARGET_ADDR_OFFSET)),
                targetAddress: formatIPv6(Buffer.from(messageBody.subarray(ICMPV6_REDIRECT_TARGET_ADDR_OFFSET, ICMPV6_REDIRECT_TARGET_ADDR_OFFSET + 16))),
                destinationAddress: formatIPv6(Buffer.from(messageBody.subarray(ICMPV6_REDIRECT_DEST_ADDR_OFFSET, ICMPV6_REDIRECT_DEST_ADDR_OFFSET + 16))),
                options: this.parseOptions(Buffer.from(messageBody.subarray(ICMPV6_REDIRECT_OPTIONS_OFFSET))),
            } as ICMPv6RedirectData;
            break;
        default:
          // For unknown types, data is the rest of the buffer after base header
          // This is already handled by the default assignment to parsedData
          break;
      }
    } catch (e) {
      if (e instanceof BufferOutOfBoundsError || e instanceof PcapDecodingError) {
        throw e; // Re-throw known decoding errors
      }
      // For other unexpected errors during specific parsing, wrap them
      throw new PcapDecodingError(`Unexpected error parsing ICMPv6 type ${type}: ${(e as Error).message}`);
    }

    const decodedLayer: ICMPv6Layer = {
      type,
      code,
      checksum,
      message,
      data: parsedData,
    };

    return {
      protocolName: this.protocolName,
      headerLength: buffer.length, // The entire ICMPv6 message
      data: decodedLayer,
      payload: Buffer.alloc(0),
    };
  }

  public nextProtocolType(_layerData: ICMPv6Layer, _context?: unknown): string | null {
    return null;
  }
}
