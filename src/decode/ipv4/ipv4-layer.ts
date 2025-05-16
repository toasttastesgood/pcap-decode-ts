/**
 * Represents the decoded data of an IPv4 (Internet Protocol version 4) layer.
 */
export interface IPv4Layer {
  /** The IP version number (should be 4). */
  version: number;
  /** Internet Header Length (IHL): The length of the IP header in 32-bit words (e.g., 5 for a 20-byte header). */
  ihl: number;
  /** Differentiated Services Code Point (DSCP): Used for Quality of Service (QoS). */
  dscp: number;
  /** Explicit Congestion Notification (ECN): Used for signaling network congestion. */
  ecn: number;
  /** Total Length: The length of the entire IP packet (header + data) in bytes. */
  totalLength: number;
  /** Identification: Used to identify fragments of an original IP datagram. */
  identification: number;
  /**
   * Flags (3 bits):
   * - Bit 0: Reserved, must be zero.
   * - Bit 1: Don't Fragment (DF).
   * - Bit 2: More Fragments (MF).
   */
  flags: number;
  /** Fragment Offset: Indicates where in the original datagram this fragment belongs (in 8-octet units). */
  fragmentOffset: number;
  /** Time To Live (TTL): Limits the lifespan of the datagram. */
  ttl: number;
  /** Protocol: Identifies the next level protocol used in the data portion of the IP datagram (e.g., 6 for TCP, 17 for UDP). */
  protocol: number;
  /** Header Checksum: A checksum on the header only. */
  headerChecksum: number;
  /** Source IP address, formatted as a string (e.g., "192.168.1.1"). */
  sourceIp: string;
  /** Destination IP address, formatted as a string (e.g., "10.0.0.1"). */
  destinationIp: string;
  /** Optional raw buffer containing IP options, if IHL > 5. */
  options?: Buffer;
}
