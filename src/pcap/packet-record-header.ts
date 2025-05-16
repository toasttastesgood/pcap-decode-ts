/**
 * Represents the header for a single packet record in a PCAP file.
 */
export interface PcapPacketRecordHeader {
  /**
   * Timestamp in seconds since the epoch (January 1, 1970, 00:00:00 UTC).
   * This indicates when the packet was captured.
   */
  ts_sec: number;

  /**
   * Timestamp in microseconds, representing the fractional part of the second
   * when the packet was captured.
   */
  ts_usec: number;

  /**
   * The number of octets of packet data actually captured and saved in this
   * packet record. This value should not exceed orig_len.
   */
  incl_len: number;

  /**
   * The actual length of the packet on the network when it was captured.
   * If incl_len is less than orig_len, the packet was truncated.
   */
  orig_len: number;
}
