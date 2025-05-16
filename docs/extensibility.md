# Extensibility API: Custom Decoders

The `pcap-decoder-ts` library is designed to be extensible, allowing users to add support for new or custom network protocols. This is achieved by implementing the `Decoder` interface and registering custom decoders with the `DecoderRegistry`.

## Core Concepts

### 1. The `Decoder` Interface

The `Decoder` interface is the cornerstone of the extensibility system. Any custom decoder must implement this interface.

```typescript
// Located in: src/decode/decoder.ts
export interface DecoderOutputLayer<TLayerData> {
  // Corrected Name
  protocolName: string;
  headerLength: number;
  data: TLayerData;
  payload: Buffer;
  context?: any;
}

export interface Decoder<TLayerData> {
  readonly protocolName: string;
  decode(buffer: Buffer, context?: any): DecoderOutputLayer<TLayerData> | null; // Corrected Name
  nextProtocolType(decodedLayer: TLayerData): number | string | null;
}
```

- **`protocolName`**: A human-readable name for your protocol (e.g., "MyCustomProtocol").
- **`decode(buffer: Buffer, context?: any)`**: This method takes a `Buffer` (starting at the beginning of your protocol's data) and an optional `context` object. It should:
  - Parse the buffer to extract your protocol's header fields.
  - Return a `DecodedPacketLayer` object containing:
    - `protocolName`: Your protocol's name.
    - `headerLength`: The length of your protocol's header in bytes.
    - `data`: An object containing the parsed fields from your protocol's header.
    - `payload`: A `Buffer` containing the remaining data after your protocol's header (this will be passed to the next decoder).
    - `context` (optional): Any additional information or errors.
  - If the buffer cannot be parsed as your protocol, it should return `null`.
- **`nextProtocolType(decodedLayer: TLayerData)`**: This method takes the `data` object returned by your `decode` method. It should:
  - Determine the protocol type of the encapsulated payload (e.g., from a "next protocol" field in your header).
  - Return a protocol identifier (number or string) that the `DecoderRegistry` will use to find the next decoder.
  - Return `null` if your protocol is the last layer or the next type cannot be determined.

### 2. The `DecoderRegistry` Class

The `DecoderRegistry` is responsible for managing all available decoders, including custom ones.

```typescript
// Located in: src/decode/decoder-registry.ts
export class DecoderRegistry {
  public registerDecoder(
    protocolId: number | string,
    decoder: Decoder<any>,
    priority: number = 0,
  ): void;
  public getDecoder(protocolId: number | string): Decoder<any> | undefined;
}
```

- **`registerDecoder(protocolId, decoder, priority?)`**:
  - `protocolId`: A unique identifier for the protocol that _precedes_ your custom protocol. For example, if your custom protocol is carried directly within an Ethernet II frame, this `protocolId` would be its EtherType. If it's carried over UDP, this would be the UDP port number.
  - `decoder`: An instance of your custom decoder.
  - `priority` (optional, default `0`): A number indicating the decoder's priority. Lower numbers mean higher priority. If multiple decoders are registered for the same `protocolId`, the one with the highest priority (lowest number) is chosen. This allows overriding default decoders or handling ambiguous protocol IDs.
- **`getDecoder(protocolId)`**: Retrieves the highest-priority decoder registered for the given `protocolId`.

## Creating and Using a Custom Decoder: Step-by-Step

Let's create a simple custom protocol called "SimpleProtocol". Assume SimpleProtocol has a 2-byte header:

- Byte 0: `type` (1 byte) - An arbitrary type field for our protocol.
- Byte 1: `nextProto` (1 byte) - The protocol ID of the encapsulated data (e.g., 6 for TCP, 17 for UDP).

### Step 1: Implement the `Decoder` Interface

```typescript
import { Decoder, DecoderOutputLayer } from 'pcap-decoder-ts'; // Adjust path as needed

// Define the structure of our custom protocol's data
interface SimpleProtocolData {
  type: number;
  nextProto: number;
}

class SimpleProtocolDecoder implements Decoder<SimpleProtocolData> {
  public readonly protocolName = 'SimpleProtocol';

  public decode(buffer: Buffer, context?: any): DecoderOutputLayer<SimpleProtocolData> | null {
    // Our header is 2 bytes. If buffer is smaller, it's not our protocol.
    if (buffer.length < 2) {
      console.log(`${this.protocolName}: Buffer too small (${buffer.length} bytes)`);
      return null;
    }

    const type = buffer.readUInt8(0);
    const nextProto = buffer.readUInt8(1);
    const headerLength = 2;

    const data: SimpleProtocolData = { type, nextProto };

    return {
      protocolName: this.protocolName,
      headerLength,
      data,
      payload: buffer.subarray(headerLength), // The rest of the buffer is the payload
    };
  }

  public nextProtocolType(decodedLayer: SimpleProtocolData): number | string | null {
    // The 'nextProto' field in our header tells us the type of the next protocol.
    return decodedLayer.nextProto;
  }
}
```

### Step 2: Instantiate `DecoderRegistry` and Register the Custom Decoder

Let's assume our `SimpleProtocol` is identified by an EtherType of `0x88B7` when carried directly over Ethernet II.

```typescript
import { DecoderRegistry } from 'pcap-decoder-ts'; // Adjust path as needed
// ... (SimpleProtocolDecoder implementation from above)

// 1. Create a DecoderRegistry instance
const registry = new DecoderRegistry();

// 2. Create an instance of our custom decoder
const simpleProtocolDecoder = new SimpleProtocolDecoder();

// 3. Register the decoder
// We're saying: "If an Ethernet II frame has EtherType 0x88B7,
// use SimpleProtocolDecoder to decode its payload."
const ETHERTYPE_SIMPLE_PROTOCOL = 0x88b7;
registry.registerDecoder(ETHERTYPE_SIMPLE_PROTOCOL, simpleProtocolDecoder);

console.log(
  `Registered ${simpleProtocolDecoder.protocolName} for EtherType ${ETHERTYPE_SIMPLE_PROTOCOL.toString(16)}`,
);
```

### Step 3: How the Decoding Pipeline Uses the Custom Decoder

The main packet decoding function (e.g., `decodePacket` from `src/decode/packet-decoder.ts`, not shown here but assumed for this example) would use the `DecoderRegistry`.

Let's imagine a simplified `decodePacket` flow:

```typescript
// Hypothetical simplified decodePacket function
/*
function decodePacket(initialBuffer: Buffer, initialProtocolId: string | number, registry: DecoderRegistry): DecodedPacketLayer<any>[] {
  let currentBuffer = initialBuffer;
  let currentProtocolId: string | number | null = initialProtocolId;
  const decodedLayers: DecodedPacketLayer<any>[] = [];

  while (currentProtocolId !== null) {
    const decoder = registry.getDecoder(currentProtocolId);
    if (!decoder) {
      console.log(`No decoder found for protocol ID: ${currentProtocolId}`);
      break; // Stop if no decoder is found
    }

    const decodedLayer = decoder.decode(currentBuffer);
    if (!decodedLayer) {
      console.log(`${decoder.protocolName} failed to decode or buffer not recognized.`);
      break; // Stop if decoding fails
    }

    decodedLayers.push(decodedLayer);
    currentBuffer = decodedLayer.payload;
    currentProtocolId = decoder.nextProtocolType(decodedLayer.data);

    if (decodedLayer.payload.length === 0 && currentProtocolId !== null) {
        console.log(`${decoder.protocolName} indicated next protocol ${currentProtocolId}, but payload is empty.`);
        break;
    }
  }
  return decodedLayers;
}
*/

// Example Usage (assuming an Ethernet II frame carrying SimpleProtocol):
// const ethernetFrameBuffer = Buffer.from([...]); // Raw bytes of an Ethernet frame
// const LINKTYPE_ETHERNET = 1; // Standard link-layer header type for Ethernet

// The main decode function would typically start with a base decoder (e.g., Ethernet)
// For this example, let's assume an Ethernet decoder has already processed the frame
// and determined the EtherType is 0x88B7, and `payloadOfEthernet` is its payload.

// const payloadOfEthernet = Buffer.from([0x01, 0x06, ...]); // SimpleProtocol type 1, nextProto TCP (6)
// const simpleProtoLayer = simpleProtocolDecoder.decode(payloadOfEthernet);

// if (simpleProtoLayer) {
//   console.log('Decoded SimpleProtocol Layer:', simpleProtoLayer);
//   const nextProtoId = simpleProtocolDecoder.nextProtocolType(simpleProtoLayer.data); // Should be 6 (TCP)
//   console.log('Next protocol ID:', nextProtoId);

//   // The main decoding loop would then use `registry.getDecoder(nextProtoId)`
//   // to find the TCP decoder and continue decoding `simpleProtoLayer.payload`.
// }
```

In a complete decoding pipeline (like the one in `src/decode/packet-decoder.ts`), the process starts with an initial decoder (e.g., for Ethernet based on the link type). This decoder processes its layer, calls `nextProtocolType` to get the EtherType (e.g., `0x88B7`), and then the pipeline uses `registry.getDecoder(0x88B7)`. This retrieves our `SimpleProtocolDecoder`.

Our `SimpleProtocolDecoder` then:

1. Decodes its 2-byte header.
2. Its `nextProtocolType` method returns the value from its `nextProto` field (e.g., `6` for TCP).
3. The pipeline then calls `registry.getDecoder(6)` to get the TCP decoder, which processes the payload of our `SimpleProtocol` layer.

### Role of `protocolId` and `priority`

- **`protocolId`**: This is crucial for linking decoders. It's the "key" used to look up the _next_ decoder in the chain. The `protocolId` you register your decoder with is the identifier that the _previous_ layer's decoder will return from its `nextProtocolType` method.

  - For Ethernet payload: EtherType (e.g., `0x0800` for IPv4, `0x88B7` for our custom one).
  - For IPv4 payload: Protocol number (e.g., `6` for TCP, `17` for UDP).
  - For TCP/UDP payload: Port number (can be used to identify application-layer protocols).

- **`priority`**: This determines which decoder is chosen if multiple decoders are registered for the _same_ `protocolId`.

  - Lower numbers = higher priority.
  - Default priority is `0`.
  - Use a negative number (e.g., `-10`) for your custom decoder if you want it to take precedence over a built-in decoder that might handle the same `protocolId` (perhaps with a different interpretation or as a fallback).
  - Use a positive number (e.g., `10`) if your decoder should only be used if no higher-priority decoders match.

  Example:

  ```typescript
  const registry = new DecoderRegistry();
  const genericHandler = new GenericDecoderForPort80(); // Priority 0 (default)
  const specificHttpHandler = new MySpecificHttpDecoder(); // Higher priority

  registry.registerDecoder(80, genericHandler); // For TCP/UDP port 80
  registry.registerDecoder(80, specificHttpHandler, -5); // Also for port 80

  // When registry.getDecoder(80) is called, it will return specificHttpHandler.
  ```

This extensibility mechanism allows for a flexible and powerful way to extend the `pcap-decoder-ts` library to support a wide range of network protocols.
