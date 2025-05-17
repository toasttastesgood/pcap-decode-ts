import { Buffer } from 'buffer'; // Ensure Buffer is imported if not already globally available in context

/**
 * Base structure for ICMPv4 type-specific data.
 */
interface ICMPv4BaseData {
  // Common fields can be added here if any, but ICMP is quite varied.
}

/**
 * Data for ICMPv4 Echo or Echo Reply messages (Type 8 or 0).
 */
export interface ICMPv4EchoData extends ICMPv4BaseData {
  identifier: number;
  sequenceNumber: number;
  echoData: Buffer;
}

/**
 * Data for ICMPv4 Destination Unreachable messages (Type 3).
 */
export interface ICMPv4DestinationUnreachableData extends ICMPv4BaseData {
  // For code 4 (Fragmentation Needed and DF was Set), this field is Next-Hop MTU.
  // For other codes, these 4 bytes are unused (must be zero).
  nextHopMtu?: number; // Only if code === 4
  unused?: Buffer; // Only if code !== 4, 4 bytes
  originalIpHeader: Buffer; // Typically the IP header of the datagram that caused the error
  originalData: Buffer; // Typically the first 8 bytes of the original datagram's payload
}

/**
 * Data for ICMPv4 Time Exceeded messages (Type 11).
 */
export interface ICMPv4TimeExceededData extends ICMPv4BaseData {
  unused: Buffer; // 4 bytes, must be zero
  originalIpHeader: Buffer;
  originalData: Buffer;
}

/**
 * Data for ICMPv4 Redirect messages (Type 5).
 */
export interface ICMPv4RedirectData extends ICMPv4BaseData {
  gatewayAddress: string; // IPv4 address of the gateway
  originalIpHeader: Buffer;
  originalData: Buffer;
}

/**
 * Data for ICMPv4 Timestamp or Timestamp Reply messages (Type 13 or 14).
 */
export interface ICMPv4TimestampData extends ICMPv4BaseData {
  identifier: number;
  sequenceNumber: number;
  originateTimestamp: number;
  receiveTimestamp: number;
  transmitTimestamp: number;
}

/**
 * Data for ICMPv4 Address Mask Request or Reply messages (Type 17 or 18).
 */
export interface ICMPv4AddressMaskData extends ICMPv4BaseData {
  identifier: number;
  sequenceNumber: number;
  addressMask: string; // IPv4 address mask
}

/**
 * Data for ICMPv4 Parameter Problem messages (Type 12).
 */
export interface ICMPv4ParameterProblemData extends ICMPv4BaseData {
  pointer: number; // Octet offset where error was detected
  unusedOrSpecific?: Buffer; // 3 bytes, usage depends on code or future RFCs
  originalIpHeader: Buffer;
  originalData: Buffer;
}

/**
 * Entry for ICMPv4 Router Advertisement messages.
 */
export interface ICMPv4RouterAdvertisementEntry {
  routerAddress: string; // IPv4 address
  preferenceLevel: number; // Signed 32-bit integer
}

/**
 * Data for ICMPv4 Router Advertisement messages (Type 9).
 */
export interface ICMPv4RouterAdvertisementData extends ICMPv4BaseData {
  numAddrs: number;
  addrEntrySize: number; // Should be 2 (for 2x 32-bit words per entry)
  lifetime: number; // In seconds
  addresses: ICMPv4RouterAdvertisementEntry[];
}

/**
 * Data for ICMPv4 Router Solicitation messages (Type 10).
 */
export interface ICMPv4RouterSolicitationData extends ICMPv4BaseData {
  reserved: Buffer; // 4 bytes, must be zero
}

/**
 * Represents the decoded ICMPv4 layer data.
 */
export interface ICMPv4Layer {
  /** The ICMP message type. */
  type: number;
  /** The ICMP message code. */
  code: number;
  /** The ICMP message checksum. */
  checksum: number;
  /** A human-readable description of the ICMP message type and code. */
  message?: string;
  /** Optional flag indicating if the received checksum was valid. */
  validChecksum?: boolean;
  /**
   * Type-specific data. This is a union of interfaces for common ICMP types,
   * or a raw Buffer for unparsed/unknown types.
   */
  data:
    | ICMPv4EchoData
    | ICMPv4DestinationUnreachableData
    | ICMPv4TimeExceededData
    | ICMPv4RedirectData
    | ICMPv4TimestampData
    | ICMPv4AddressMaskData
    | ICMPv4ParameterProblemData
    | ICMPv4RouterAdvertisementData
    | ICMPv4RouterSolicitationData
    | Buffer; // Fallback for unknown or unparsed types
}
