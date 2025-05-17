import { describe, it, expect } from 'vitest';
import { DecoderRegistry } from '../../decode/decoder-registry';
// DecoderOutputLayer is the generic type returned by a Decoder's decode method
import { type Decoder, type DecoderOutputLayer } from '../../decode/decoder';
// PacketSpecificLayer is the non-generic type used in DecodedPacket.layers
import { decodePacket } from '../../decode/packet-decoder';
import { type DecodedPacketLayer as PacketSpecificLayer } from '../../decode/packet-structures';

// Define a simple mock custom protocol: FixedHeaderProtocol
// Header:
// - 2 bytes: magicNumber (must be 0xCAFE)
// - 1 byte: payloadType (e.g., an identifier for what's next)
// - 1 byte: payloadLength (length of the actual payload, not including this header)
interface FixedHeaderProtocolData {
  magicNumber: number;
  payloadType: number;
  actualPayload: Buffer;
  instanceId: string; // Added to verify which decoder instance ran
}

const FIXED_HEADER_MAGIC_NUMBER = 0xcafe;
const FIXED_HEADER_LENGTH = 4;

class FixedHeaderProtocolDecoder implements Decoder<FixedHeaderProtocolData> {
  public readonly protocolName = 'FixedHeaderProtocol';
  private id: string;

  constructor(id: string = 'default') {
    this.id = id; // To differentiate instances in priority test
  }

  public decode(
    buffer: Buffer,
    _context?: unknown,
  ): DecoderOutputLayer<FixedHeaderProtocolData> | null {
    if (buffer.length < FIXED_HEADER_LENGTH) {
      return null;
    }

    const magicNumber = buffer.readUInt16BE(0);
    if (magicNumber !== FIXED_HEADER_MAGIC_NUMBER) {
      return null;
    }

    const payloadType = buffer.readUInt8(2);
    const payloadLength = buffer.readUInt8(3);

    if (buffer.length < FIXED_HEADER_LENGTH + payloadLength) {
      return null;
    }

    const actualPayload = buffer.subarray(FIXED_HEADER_LENGTH, FIXED_HEADER_LENGTH + payloadLength);

    return {
      protocolName: this.protocolName,
      headerLength: FIXED_HEADER_LENGTH,
      data: {
        magicNumber,
        payloadType,
        actualPayload,
        instanceId: this.id, // Include instanceId in the data
      },
      payload: buffer.subarray(FIXED_HEADER_LENGTH + payloadLength),
    };
  }

  public nextProtocolType(decodedLayer: FixedHeaderProtocolData): number | string | null {
    // The 'payloadType' field in our header determines the next protocol.
    return decodedLayer.payloadType;
  }
}

// Another simple decoder for testing the "next" protocol
interface SimplePayloadData {
  content: string;
}
const MOCK_PAYLOAD_PROTOCOL_ID = 0xff; // Arbitrary ID for the payload

class SimplePayloadDecoder implements Decoder<SimplePayloadData> {
  public readonly protocolName = 'SimplePayload';

  decode(buffer: Buffer, _context?: unknown): DecoderOutputLayer<SimplePayloadData> | null {
    if (buffer.length === 0) return null;
    return {
      protocolName: this.protocolName,
      headerLength: buffer.length, // Consumes the whole buffer
      data: { content: buffer.toString('utf-8') },
      payload: Buffer.alloc(0),
    };
  }

  nextProtocolType(_decodedLayer: SimplePayloadData): string | number | null {
    return null; // This is the last layer
  }
}

describe('Decoder Extensibility E2E', () => {
  it('should register and use a custom decoder for a mock protocol', () => {
    const registry = new DecoderRegistry();
    const customDecoder = new FixedHeaderProtocolDecoder(); // Uses 'default' id
    const NUMERIC_MOCK_PROTOCOL_ID = 0xabcd;

    registry.registerDecoder(NUMERIC_MOCK_PROTOCOL_ID, customDecoder);

    const payloadContent = 'HELLO';
    const packetBuffer = Buffer.alloc(FIXED_HEADER_LENGTH + payloadContent.length);
    packetBuffer.writeUInt16BE(FIXED_HEADER_MAGIC_NUMBER, 0);
    packetBuffer.writeUInt8(MOCK_PAYLOAD_PROTOCOL_ID, 2);
    packetBuffer.writeUInt8(payloadContent.length, 3);
    packetBuffer.write(payloadContent, FIXED_HEADER_LENGTH);

    const payloadDecoder = new SimplePayloadDecoder();
    registry.registerDecoder(MOCK_PAYLOAD_PROTOCOL_ID, payloadDecoder);

    const decodedPacket = decodePacket(packetBuffer, NUMERIC_MOCK_PROTOCOL_ID, registry);

    expect(decodedPacket.layers).toHaveLength(2);

    const customLayer = decodedPacket.layers[0] as PacketSpecificLayer;
    expect(customLayer.protocolName).toBe('FixedHeaderProtocol');
    const customLayerData = customLayer.data as FixedHeaderProtocolData;
    expect(customLayerData.magicNumber).toBe(FIXED_HEADER_MAGIC_NUMBER);
    expect(customLayerData.payloadType).toBe(MOCK_PAYLOAD_PROTOCOL_ID);
    expect(customLayerData.actualPayload.toString('utf-8')).toBe(payloadContent);
    expect(customLayerData.instanceId).toBe('default');
    expect(customLayer.bytes.length).toBe(FIXED_HEADER_LENGTH);
    expect(customLayer.payload?.toString('utf-8')).toBe(payloadContent);

    const nextLayer = decodedPacket.layers[1] as PacketSpecificLayer;
    expect(nextLayer.protocolName).toBe('SimplePayload');
    const nextLayerData = nextLayer.data as SimplePayloadData;
    expect(nextLayerData.content).toBe(payloadContent);
    expect(nextLayer.bytes.length).toBe(payloadContent.length);
    expect(nextLayer.payload?.length).toBe(0);
  });

  it('should respect decoder priority', () => {
    const registry = new DecoderRegistry();
    const NUMERIC_MOCK_PROTOCOL_ID_PRIORITY = 0xabce;

    const lowPriorityDecoder = new FixedHeaderProtocolDecoder('low_priority');
    const highPriorityDecoder = new FixedHeaderProtocolDecoder('high_priority');

    registry.registerDecoder(NUMERIC_MOCK_PROTOCOL_ID_PRIORITY, lowPriorityDecoder, 10);
    registry.registerDecoder(NUMERIC_MOCK_PROTOCOL_ID_PRIORITY, highPriorityDecoder, -10);

    const packetBuffer = Buffer.alloc(FIXED_HEADER_LENGTH);
    packetBuffer.writeUInt16BE(FIXED_HEADER_MAGIC_NUMBER, 0);
    packetBuffer.writeUInt8(0x00, 2);
    packetBuffer.writeUInt8(0, 3);

    const decodedPacket = decodePacket(packetBuffer, NUMERIC_MOCK_PROTOCOL_ID_PRIORITY, registry);

    expect(decodedPacket.layers).toHaveLength(1);
    const customLayer = decodedPacket.layers[0] as PacketSpecificLayer;
    expect(customLayer.protocolName).toBe('FixedHeaderProtocol');
    const customLayerData = customLayer.data as FixedHeaderProtocolData;
    expect(customLayerData.instanceId).toBe('high_priority');
  });

  it('should use the first registered decoder if priorities are the same (due to sort stability)', () => {
    const registry = new DecoderRegistry();
    const NUMERIC_MOCK_PROTOCOL_ID_SAME_PRIORITY = 0xabcf;

    const decoder1 = new FixedHeaderProtocolDecoder('decoder1_same_priority');
    const decoder2 = new FixedHeaderProtocolDecoder('decoder2_same_priority');

    registry.registerDecoder(NUMERIC_MOCK_PROTOCOL_ID_SAME_PRIORITY, decoder1, 5);
    registry.registerDecoder(NUMERIC_MOCK_PROTOCOL_ID_SAME_PRIORITY, decoder2, 5);

    const packetBuffer = Buffer.alloc(FIXED_HEADER_LENGTH);
    packetBuffer.writeUInt16BE(FIXED_HEADER_MAGIC_NUMBER, 0);
    packetBuffer.writeUInt8(0x00, 2);
    packetBuffer.writeUInt8(0, 3);

    const decodedPacket = decodePacket(
      packetBuffer,
      NUMERIC_MOCK_PROTOCOL_ID_SAME_PRIORITY,
      registry,
    );

    expect(decodedPacket.layers).toHaveLength(1);
    const customLayer = decodedPacket.layers[0] as PacketSpecificLayer;
    expect(customLayer.protocolName).toBe('FixedHeaderProtocol');
    const customLayerData = customLayer.data as FixedHeaderProtocolData;
    expect(customLayerData.instanceId).toBe('decoder1_same_priority');
  });

  it('should produce Raw Data layer if custom decoder fails to parse (e.g. wrong magic number)', () => {
    const registry = new DecoderRegistry();
    const customDecoder = new FixedHeaderProtocolDecoder();
    const NUMERIC_MOCK_PROTOCOL_ID_FAIL = 0xabdd; // Unique ID for this test

    registry.registerDecoder(NUMERIC_MOCK_PROTOCOL_ID_FAIL, customDecoder);

    const payloadContent = 'SHOULD_BE_RAW';
    const packetBuffer = Buffer.alloc(FIXED_HEADER_LENGTH + payloadContent.length);
    packetBuffer.writeUInt16BE(0xDEAD, 0); // WRONG Magic number
    packetBuffer.writeUInt8(MOCK_PAYLOAD_PROTOCOL_ID, 2);
    packetBuffer.writeUInt8(payloadContent.length, 3);
    packetBuffer.write(payloadContent, FIXED_HEADER_LENGTH);

    const decodedPacket = decodePacket(packetBuffer, NUMERIC_MOCK_PROTOCOL_ID_FAIL, registry);

    // Expecting one layer, which should be 'Raw Data' as the custom decoder failed
    expect(decodedPacket.layers).toHaveLength(1);
    const rawLayer = decodedPacket.layers[0];
    expect(rawLayer.protocolName).toBe('Raw Data');
    expect(rawLayer.bytes.equals(packetBuffer)).toBe(true);
    // Check that there's no 'data' or 'payload' field on RawPayloadLayer beyond the base
    expect(rawLayer).not.toHaveProperty('data');
    expect(rawLayer).not.toHaveProperty('payload');
  });
});
