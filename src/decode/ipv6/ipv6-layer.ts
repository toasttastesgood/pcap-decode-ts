/**
 * Represents the decoded data of an IPv6 (Internet Protocol version 6) layer.
 * This interface covers the fields in the fixed IPv6 header.
 */
export interface IPv6Layer {
  /** The IP version number (should be 6). */
  version: number;
  /** Traffic Class: Used for Quality of Service (QoS). */
  trafficClass: number;
  /** Flow Label: Used for labeling sequences of packets requiring special handling. */
  flowLabel: number;
  /** Payload Length: The length of the IPv6 payload (the part of the packet following the IPv6 header) in octets. */
  payloadLength: number;
  /** Next Header: Identifies the type of header immediately following the IPv6 header (e.g., 6 for TCP, 17 for UDP, 58 for ICMPv6). */
  nextHeader: number;
  /** Hop Limit: Limits the lifespan of the datagram, decremented by each router. */
  hopLimit: number;
  /** Source IPv6 address, formatted as a string (e.g., "2001:db8::1"). */
  sourceIp: string;
  /** Destination IPv6 address, formatted as a string (e.g., "2001:db8::2"). */
  destinationIp: string;
}
