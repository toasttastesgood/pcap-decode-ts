/**
 * Represents the decoded ICMPv4 layer data.
 */
export interface ICMPv4Layer {
  /**
   * The ICMP message type.
   */
  type: number;

  /**
   * The ICMP message code.
   */
  code: number;

  /**
   * The ICMP message checksum.
   */
  checksum: number;

  /**
   * Type-specific data. This can be a Buffer or a union of interfaces
   * for common ICMP types. For now, it's a generic Buffer.
   */
  data: Buffer;
}
