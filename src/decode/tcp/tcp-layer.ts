/**
 * Represents the decoded TCP layer data.
 */
export interface TCPLayer {
  /** Source port */
  sourcePort: number;
  /** Destination port */
  destinationPort: number;
  /** Sequence number */
  sequenceNumber: number;
  /** Acknowledgment number */
  acknowledgmentNumber: number;
  /** Data offset (header length in 32-bit words) */
  dataOffset: number;
  /** Reserved bits */
  reserved: number;
  /** TCP flags */
  flags: {
    /** Nonce Sum */
    ns: boolean;
    /** Congestion Window Reduced */
    cwr: boolean;
    /** ECN-Echo */
    ece: boolean;
    /** Urgent pointer field is significant */
    urg: boolean;
    /** Acknowledgment field is significant */
    ack: boolean;
    /** Push function */
    psh: boolean;
    /** Reset the connection */
    rst: boolean;
    /** Synchronize sequence numbers */
    syn: boolean;
    /** No more data from sender */
    fin: boolean;
  };
  /** Window size */
  windowSize: number;
  /** Checksum */
  checksum: number;
  /** Urgent pointer */
  urgentPointer: number;
  /** TCP options (raw buffer if Data Offset > 5) */
  options?: Buffer;
}
