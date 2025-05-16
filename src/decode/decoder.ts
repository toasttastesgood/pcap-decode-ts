/**
 * Represents a decoded layer of a packet.
 * @template TLayerData The type of the parsed data for this specific layer.
 */
export interface DecoderOutputLayer<TLayerData> {
  /** The name of the protocol for this layer (e.g., "Ethernet II", "IPv4"). */
  protocolName: string;
  /** The length of the header for this layer in bytes. */
  headerLength: number;
  /** The parsed data specific to this protocol layer. */
  data: TLayerData;
  /** The remaining buffer after this layer's header, representing the payload. */
  payload: Buffer;
  /** Optional additional context or errors encountered during decoding. */
  context?: unknown; // Can be refined further if needed
}

/**
 * Defines the contract for all protocol decoders.
 * Users can implement this interface to create custom decoders for new or unsupported protocols.
 *
 * @template TLayerData The type of the structured data this decoder will produce for its layer.
 *
 * @example
 * ```typescript
 * // Example of a simple custom decoder implementation
 * interface MyProtocolData {
 *   fieldA: number;
 *   fieldB: string;
 * }
 *
 * class MyCustomDecoder implements Decoder<MyProtocolData> {
 *   public readonly protocolName = "MyCustomProtocol";
 *
 *   public decode(buffer: Buffer, context?: any): DecoderOutputLayer<MyProtocolData> | null {
 *     if (buffer.length < 5) return null; // Not enough data for our protocol
 *
 *     const fieldA = buffer.readUInt8(0);
 *     const fieldB = buffer.toString('utf-8', 1, 5);
 *     const headerLength = 5;
 *
 *     return {
 *       protocolName: this.protocolName,
 *       headerLength,
 *       data: { fieldA, fieldB },
 *       payload: buffer.subarray(headerLength),
 *     };
 *   }
 *
 *   public nextProtocolType(decodedLayer: MyProtocolData): number | string | null {
 *     // Example: if MyProtocol always encapsulates TCP (protocol number 6)
 *     // Or, determine from a field in MyProtocolData
 *     return 6; // Or null if it's the last layer or type is unknown
 *   }
 * }
 * ```
 */
export interface Decoder<TLayerData> {
  /**
   * A human-readable name for the protocol this decoder handles.
   * This name will be used in the `protocolName` field of the {@link DecoderOutputLayer}.
   * @example "Ethernet II", "IPv4", "TCP", "MyCustomProtocol"
   */
  readonly protocolName: string;

  /**
   * Decodes the provided buffer into a structured representation of the protocol layer.
   *
   * This method is responsible for:
   * 1. Validating if the buffer contains a valid packet for this protocol.
   * 2. Parsing the header fields from the buffer.
   * 3. Determining the length of the header.
   * 4. Extracting the payload (the rest of the buffer after the header).
   *
   * If the buffer cannot be decoded as this protocol (e.g., insufficient length, invalid fields),
   * this method should return `null`.
   *
   * @param buffer The raw byte buffer containing the packet data, starting at the beginning of this protocol's layer.
   * @param context Optional context information passed down from preceding decoders or the initial decoding call.
   *                This can be used for protocols where decoding depends on information from a previous layer
   *                (e.g., IPv6 jumbo-grams length from a Hop-by-Hop Options header).
   * @returns A {@link DecoderOutputLayer} object containing the parsed data, header length, and payload
   *          if decoding is successful. Returns `null` if the buffer does not represent a valid packet
   *          for this protocol, allowing the {@link DecoderRegistry} to try other decoders if applicable.
   */
  decode(buffer: Buffer, context?: unknown): DecoderOutputLayer<TLayerData> | null;

  /**
   * Determines the protocol identifier for the next layer encapsulated by this protocol.
   * This is typically derived from a specific field in the current protocol's header
   * (e.g., the "EtherType" field in an Ethernet II frame, or the "Protocol" field in an IPv4 header).
   *
   * The returned value will be used by the {@link DecoderRegistry} to find the appropriate decoder
   * for the payload of the current layer.
   *
   * @param decodedLayer The structured data of the current layer, as returned by the `decode` method.
   *                     This object contains the parsed fields from which the next protocol type can be derived.
   * @returns The protocol type identifier (e.g., a number like `0x0800` for IPv4 over Ethernet,
   *          or a string if using string-based identifiers) for the next layer.
   *          Returns `null` if this protocol layer is the last one in the packet (i.e., it encapsulates no further protocol),
   *          or if the next protocol type cannot be determined from the header.
   */
  nextProtocolType(decodedLayer: TLayerData): number | string | null;
}
