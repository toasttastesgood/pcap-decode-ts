/**
 * Represents the global header of a PCAP file.
 */
export interface PcapGlobalHeader {
  /**
   * Magic number (0xa1b2c3d4 or 0xd4c3b2a1).
   * Indicates the byte order of the file.
   */
  magic_number: number;

  /**
   * Major version number of the PCAP file format.
   */
  version_major: number;

  /**
   * Minor version number of the PCAP file format.
   */
  version_minor: number;

  /**
   * GMT to local correction.
   * In practice, this is usually 0.
   */
  thiszone: number;

  /**
   * Accuracy of timestamps.
   * In practice, this is usually 0.
   */
  sigfigs: number;

  /**
   * Snapshot length.
   * Maximum number of octets captured from each packet.
   */
  snaplen: number;

  /**
   * Link-layer header type (e.g., Ethernet, Wi-Fi).
   * Specifies the type of link-layer headers used in the packets.
   */
  network: number;
}
