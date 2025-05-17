import { Buffer } from 'buffer';

/**
 * Base structure for ICMPv6 type-specific data.
 */
interface ICMPv6BaseData {}

/**
 * Represents a generic ICMPv6 Option (e.g., for NDP).
 * RFC 4861, Section 4.6
 */
export interface ICMPv6Option {
  type: number;
  length: number; // Length of the option in units of 8 octets
  linkLayerAddress?: string; // For type 1 (Source LLA) and 2 (Target LLA)
  prefix?: { // For type 3 (Prefix Information)
    prefixLength: number;
    flags: { L: boolean; A: boolean; R?: boolean }; // R is for Router Address flag (RFC 3775)
    validLifetime: number;
    preferredLifetime: number;
    prefixAddress: string; // IPv6 address
  };
  mtu?: number; // For type 5 (MTU)
  rawData: Buffer; // Raw data of the option, excluding type and length
}

/**
 * Data for ICMPv6 Echo Request or Echo Reply messages (Type 128 or 129).
 */
export interface ICMPv6EchoData extends ICMPv6BaseData {
  identifier: number;
  sequenceNumber: number;
  echoData: Buffer;
}

/**
 * Data for ICMPv6 Destination Unreachable messages (Type 1).
 */
export interface ICMPv6DestinationUnreachableData extends ICMPv6BaseData {
  unused: Buffer; // 4 bytes, typically zero
  // As much of invoking packet as possible without the ICMPv6 packet exceeding the minimum IPv6 MTU.
  originalPacketData: Buffer;
}

/**
 * Data for ICMPv6 Packet Too Big messages (Type 2).
 */
export interface ICMPv6PacketTooBigData extends ICMPv6BaseData {
  mtu: number;
  // As much of invoking packet as possible without the ICMPv6 packet exceeding the minimum IPv6 MTU.
  originalPacketData: Buffer;
}

/**
 * Data for ICMPv6 Time Exceeded messages (Type 3).
 */
export interface ICMPv6TimeExceededData extends ICMPv6BaseData {
  unused: Buffer; // 4 bytes, typically zero
  originalPacketData: Buffer;
}

/**
 * Data for ICMPv6 Parameter Problem messages (Type 4).
 */
export interface ICMPv6ParameterProblemData extends ICMPv6BaseData {
  pointer: number; // Identifies the octet offset within the invoking packet where the error was detected.
  originalPacketData: Buffer;
}

/**
 * Data for ICMPv6 Router Solicitation messages (Type 133).
 * RFC 4861
 */
export interface ICMPv6RouterSolicitationData extends ICMPv6BaseData {
  reserved: Buffer; // 4 bytes
  options: ICMPv6Option[];
}

/**
 * Data for ICMPv6 Router Advertisement messages (Type 134).
 * RFC 4861
 */
export interface ICMPv6RouterAdvertisementData extends ICMPv6BaseData {
  currentHopLimit: number;
  flags: { M: boolean; O: boolean; H?: boolean /* Home Agent, RFC 3775 */ }; // M: Managed address configuration, O: Other configuration
  routerLifetime: number; // In seconds
  reachableTime: number; // In milliseconds
  retransTimer: number; // In milliseconds
  options: ICMPv6Option[];
}

/**
 * Data for ICMPv6 Neighbor Solicitation messages (Type 135).
 * RFC 4861
 */
export interface ICMPv6NeighborSolicitationData extends ICMPv6BaseData {
  reserved: Buffer; // 4 bytes
  targetAddress: string; // IPv6 address
  options: ICMPv6Option[];
}

/**
 * Data for ICMPv6 Neighbor Advertisement messages (Type 136).
 * RFC 4861
 */
export interface ICMPv6NeighborAdvertisementData extends ICMPv6BaseData {
  flags: { R: boolean; S: boolean; O: boolean }; // R: Router, S: Solicited, O: Override
  targetAddress: string; // IPv6 address
  options: ICMPv6Option[];
}

/**
 * Data for ICMPv6 Redirect messages (Type 137).
 * RFC 4861
 */
export interface ICMPv6RedirectData extends ICMPv6BaseData {
  reserved: Buffer; // 4 bytes
  targetAddress: string; // IPv6 address
  destinationAddress: string; // IPv6 address
  options: ICMPv6Option[];
}

/**
 * Represents the decoded ICMPv6 layer data.
 */
export interface ICMPv6Layer {
  /** The ICMPv6 message type. */
  type: number;
  /** The ICMPv6 message code. */
  code: number;
  /** The ICMPv6 message checksum. */
  checksum: number;
  /** A human-readable description of the ICMPv6 message type and code. */
  message?: string;
  /**
   * Type-specific data. This is a union of interfaces for common ICMPv6 types,
   * or a raw Buffer for unparsed/unknown types.
   */
  data:
    | ICMPv6EchoData
    | ICMPv6DestinationUnreachableData
    | ICMPv6PacketTooBigData
    | ICMPv6TimeExceededData
    | ICMPv6ParameterProblemData
    | ICMPv6RouterSolicitationData
    | ICMPv6RouterAdvertisementData
    | ICMPv6NeighborSolicitationData
    | ICMPv6NeighborAdvertisementData
    | ICMPv6RedirectData
    | Buffer; // Fallback for unknown or unparsed types
}