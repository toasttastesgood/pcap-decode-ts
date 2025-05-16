import { Decoder } from './decoder';

interface RegisteredDecoder {
  decoder: Decoder<unknown>; // Can store any type of decoder
  priority: number;
}

/**
 * Manages a collection of {@link Decoder} instances and provides a mechanism
 * to retrieve the appropriate decoder for a given protocol identifier.
 *
 * This registry allows for the registration of multiple decoders for the same
 * protocol identifier, using a priority system to determine which decoder
 * should be used. This is useful for overriding default decoders or for
 * handling variations of a protocol.
 *
 * @example
 * ```typescript
 * // 1. Create a decoder registry instance
 * const registry = new DecoderRegistry();
 *
 * // 2. Create instances of your custom decoders
 * const myCustomDecoder = new MyCustomDecoder(); // Implements Decoder<MyProtocolData>
 * const anotherDecoder = new AnotherDecoder();   // Implements Decoder<AnotherProtocolData>
 *
 * // 3. Register decoders
 * // Register MyCustomDecoder for protocol ID 0xABCD with default priority (0)
 * registry.registerDecoder(0xABCD, myCustomDecoder);
 *
 * // Register AnotherDecoder for protocol ID 0x1234 with a higher priority (-1)
 * registry.registerDecoder(0x1234, anotherDecoder, -1);
 *
 * // 4. Retrieve a decoder
 * const decoderForAbcd = registry.getDecoder(0xABCD); // Returns myCustomDecoder
 * if (decoderForAbcd) {
 *   // Use the decoder
 * }
 * ```
 */
export class DecoderRegistry {
  private decoders: Map<string | number, RegisteredDecoder[]> = new Map();

  /**
   * Registers a {@link Decoder} instance with a specific protocol identifier and an optional priority.
   *
   * When multiple decoders are registered for the same `protocolId`, the one with the
   * numerically lowest `priority` value will be considered the highest priority and
   * will be returned by {@link getDecoder}. If multiple decoders share the same lowest
   * priority, the one registered most recently among them might be chosen, but this
   * behavior can be implementation-dependent due to sort stability. It's best
   * to use distinct priorities if a specific order is required.
   *
   * @param protocolId The protocol identifier that this decoder handles. This can be a
   *                   number (e.g., EtherType, IP protocol number, TCP/UDP port) or a
   *                   string (for protocols identified by unique string constants).
   * @param decoder The instance of the `Decoder` to register.
   * @param priority Optional priority for the decoder. Defaults to `0`. Lower numbers
   *                 indicate higher priority (e.g., `-1` is higher priority than `0`,
   *                 which is higher than `1`). This allows custom decoders to override
   *                 default decoders or to specify preference when multiple decoders
   *                 can handle the same protocol ID.
   *
   * @example
   * ```typescript
   * const registry = new DecoderRegistry();
   * const customIPv4Decoder = new MyCustomIPv4Decoder();
   * const standardIPv4Decoder = new StandardIPv4Decoder();
   *
   * // Register standard decoder with default priority
   * registry.registerDecoder(0x0800, standardIPv4Decoder);
   *
   * // Register custom decoder with higher priority to override the standard one
   * registry.registerDecoder(0x0800, customIPv4Decoder, -10);
   *
   * const ipv4Decoder = registry.getDecoder(0x0800); // Will be customIPv4Decoder
   * ```
   */
  public registerDecoder(
    protocolId: number | string,
    decoder: Decoder<unknown>,
    priority: number = 0,
  ): void {
    if (!this.decoders.has(protocolId)) {
      this.decoders.set(protocolId, []);
    }
    const decoderList = this.decoders.get(protocolId)!;
    // Add new decoder and re-sort. Could be optimized if performance becomes an issue
    // for very frequent registrations by inserting in sorted order.
    decoderList.push({ decoder, priority });
    // Sort by priority (ascending) so the first element is the highest priority.
    // If priorities are equal, the order of insertion is not guaranteed to be preserved
    // by Array.prototype.sort() in all JS environments, though modern ones tend to be stable.
    decoderList.sort((a, b) => a.priority - b.priority);
  }

  /**
   * Retrieves the highest-priority registered {@link Decoder} for a given protocol identifier.
   *
   * If multiple decoders are registered for the same `protocolId`, this method returns
   * the one with the numerically lowest `priority` value. If no decoders are registered
   * for the given `protocolId`, it returns `undefined`.
   *
   * @param protocolId The protocol identifier for which to retrieve a decoder.
   *                   This should match the `protocolId` used during registration.
   * @returns The {@link Decoder} instance with the highest priority for the given `protocolId`,
   *          or `undefined` if no decoder is registered for that ID.
   *
   * @example
   * ```typescript
   * const decoder = registry.getDecoder(0x0800); // For IPv4 over Ethernet
   * if (decoder) {
   *   // packetBuffer is a Buffer containing the IPv4 packet
   *   const decodedLayer = decoder.decode(packetBuffer);
   *   if (decodedLayer) {
   *     console.log(`Decoded ${decoder.protocolName}:`, decodedLayer.data);
   *   }
   * } else {
   *   console.log("No decoder found for protocol ID 0x0800");
   * }
   * ```
   */
  public getDecoder(protocolId: number | string): Decoder<unknown> | undefined {
    const decoderList = this.decoders.get(protocolId);
    if (decoderList && decoderList.length > 0) {
      // The list is sorted by priority (lowest number first),
      // so the first element has the highest priority.
      return decoderList[0].decoder;
    }
    return undefined;
  }
}
