import { Buffer } from 'buffer';

/**
 * Represents a portion of the packet data that could not be decoded
 * by any registered decoder or where decoding failed.
 */
export interface RawPayloadLayer {
  /** The fixed protocol name for raw, undecoded data. */
  protocolName: 'Raw Data';
  /** The raw bytes of the undecoded payload. */
  bytes: Buffer;
}

/**
 * Represents a successfully decoded protocol layer within a packet.
 * This is part of the final {@link DecodedPacket} structure.
 */
export interface DecodedPacketLayer {
  /** The name of the protocol for this layer (e.g., "Ethernet II", "IPv4", "TCP"). */
  protocolName: string;
  /** The parsed, structured data specific to this protocol layer. The type of this field depends on the protocol. */
  data: unknown;
  /** The raw bytes that constitute the header of this protocol layer. */
  bytes: Buffer;
  /**
   * The payload of this layer, which is the input for the next decoder in the chain.
   * This is typically a sub-array of `bytes`. Undefined if this layer has no further payload.
   */
  payload?: Buffer;
}

/**
 * Represents a fully decoded packet, including its metadata and all decoded layers.
 */
export interface DecodedPacket {
  /** Timestamp of packet capture, derived from PCAP/PCAPng headers. Can be a Date object or a numeric representation (e.g., epoch seconds or microseconds). */
  timestamp?: Date | number;
  /** The original length of the packet on the wire, in bytes. */
  originalLength: number;
  /** The length of the packet data actually captured and present in the file, in bytes. */
  capturedLength: number;
  /**
   * Optional information about the interface on which the packet was captured.
   * This is typically populated from PCAPng Interface Description Blocks.
   * The structure of this field can vary.
   */
  interfaceInfo?: unknown;
  /** An array of decoded protocol layers or raw data segments that make up the packet. */
  layers: (DecodedPacketLayer | RawPayloadLayer)[];
  // Add any other relevant metadata from PCAP/PCAPng headers here
}
