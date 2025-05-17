import { Buffer } from 'buffer';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { decodePacket } from '../../decode/packet-decoder';
import {
  DecodedPacketLayer as PacketStructureLayer,
  RawPayloadLayer,
} from '../../decode/packet-structures';
import { Decoder, DecoderOutputLayer } from '../../decode/decoder';
import { DecoderRegistry } from '../../decode/decoder-registry';
import { PcapError, PcapDecodingError } from '../../errors'; // Added PcapError imports
import * as logger from '../../utils/logger'; // Import all as logger to mock its functions

// Mock the logger functions
vi.mock('../../utils/logger', () => ({
  logWarning: vi.fn(),
  logError: vi.fn(),
  logInfo: vi.fn(),
  logDebug: vi.fn(),
}));

// --- Mock Implementations ---

// --- Mock Implementations ---

interface MockEthernetLayerData {
  sourceMac: string;
  destMac: string;
  type: number | string | null;
}
class MockEthernetDecoder implements Decoder<MockEthernetLayerData> {
  protocolName = 'MockEthernet';
  private _nextProto: number | string | null = 0x0800; // Default to IPv4
  public headerLength = 2;

  decode(buffer: Buffer, _context?: unknown): DecoderOutputLayer<MockEthernetLayerData> | null {
    if (buffer.length < this.headerLength) return null;
    const payload = buffer.subarray(this.headerLength);
    return {
      protocolName: this.protocolName,
      headerLength: this.headerLength,
      data: { sourceMac: '00:00:00:00:00:01', destMac: '00:00:00:00:00:02', type: this._nextProto },
      payload: payload.length > 0 ? payload : Buffer.alloc(0),
    };
  }

  nextProtocolType(decodedLayer: MockEthernetLayerData): number | string | null {
    return decodedLayer.type;
  }

  setNextProtocol(proto: number | string | null) {
    this._nextProto = proto;
  }
}

interface MockIPv4LayerData {
  sourceIp: string;
  destIp: string;
  protocol: number | string | null;
}
class MockIPv4Decoder implements Decoder<MockIPv4LayerData> {
  protocolName = 'MockIPv4';
  private _nextProto: number | string | null = 6; // Default to TCP
  public headerLength = 2;

  decode(buffer: Buffer, _context?: unknown): DecoderOutputLayer<MockIPv4LayerData> | null {
    if (buffer.length < this.headerLength) return null;
    const payload = buffer.subarray(this.headerLength);
    return {
      protocolName: this.protocolName,
      headerLength: this.headerLength,
      data: { sourceIp: '1.1.1.1', destIp: '2.2.2.2', protocol: this._nextProto },
      payload: payload.length > 0 ? payload : Buffer.alloc(0),
    };
  }

  nextProtocolType(decodedLayer: MockIPv4LayerData): number | string | null {
    return decodedLayer.protocol;
  }

  setNextProtocol(proto: number | string | null) {
    this._nextProto = proto;
  }
}

interface MockTCPLayerData {
  sourcePort: number;
  destPort: number;
}
class MockTCPDecoder implements Decoder<MockTCPLayerData> {
  protocolName = 'MockTCP';
  public headerLength = 2;

  decode(buffer: Buffer, _context?: unknown): DecoderOutputLayer<MockTCPLayerData> | null {
    if (buffer.length < this.headerLength) return null;
    const payload = buffer.subarray(this.headerLength);
    return {
      protocolName: this.protocolName,
      headerLength: this.headerLength,
      data: { sourcePort: 1234, destPort: 80 },
      payload: payload.length > 0 ? payload : Buffer.alloc(0),
    };
  }

  nextProtocolType(_decodedLayer: MockTCPLayerData): number | string | null {
    return null; // TCP is often the last layer in this context
  }
}

class MockErrorDecoder implements Decoder<unknown> {
  // 'any' for data type as it errors out
  protocolName = 'MockErrorDecoder';
  public headerLength = 0; // Not strictly needed as it throws

  decode(_buffer: Buffer, _context?: unknown): DecoderOutputLayer<unknown> | null {
    throw new Error('Mock decoding error');
  }

  nextProtocolType(_decodedLayer: unknown): number | string | null {
    return null;
  }
}


class MockPcapErrorDecoder implements Decoder<unknown> {
  protocolName = 'MockPcapErrorDecoder';
  public headerLength = 0;

  decode(_buffer: Buffer, _context?: unknown): DecoderOutputLayer<unknown> | null {
    throw new PcapDecodingError('Mock PcapDecodingError');
  }

  nextProtocolType(_decodedLayer: unknown): number | string | null {
    return null;
  }
}

describe('decodePacket', () => {
  let registry: DecoderRegistry;
  let mockEthernetDecoder: MockEthernetDecoder;
  let mockIPv4Decoder: MockIPv4Decoder;
  let mockTCPDecoder: MockTCPDecoder;
  let mockErrorDecoder: MockErrorDecoder;
  let mockPcapErrorDecoder: MockPcapErrorDecoder; // Added

  const ethLinkType = 1; // LINKTYPE_ETHERNET
  const ipv4ProtocolType = 0x0800;
  const tcpProtocolType = 6;
  const unknownProtocolType = 0xffff;
  const errorProtocolType = 0xeeee;
  const pcapErrorProtocolType = 0xdddd; // New type for PcapError test

  beforeEach(() => {
    registry = new DecoderRegistry();
    mockEthernetDecoder = new MockEthernetDecoder();
    mockIPv4Decoder = new MockIPv4Decoder();
    mockTCPDecoder = new MockTCPDecoder();
    mockErrorDecoder = new MockErrorDecoder();
    mockPcapErrorDecoder = new MockPcapErrorDecoder(); // Added

    registry.registerDecoder(ethLinkType, mockEthernetDecoder);
    registry.registerDecoder(ipv4ProtocolType, mockIPv4Decoder);
    registry.registerDecoder(tcpProtocolType, mockTCPDecoder);
    registry.registerDecoder(errorProtocolType, mockErrorDecoder);
    registry.registerDecoder(pcapErrorProtocolType, mockPcapErrorDecoder); // Added

    // Reset mocks
    vi.mocked(logger.logWarning).mockClear();
    vi.mocked(logger.logError).mockClear(); // logError is still mocked, though not expected for these cases
  });
  it('should correctly chain multiple decoders for a full packet', () => {
    const rawPacket = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // Eth(2) + IPv4(2) + TCP(2) + Payload(2)
    mockEthernetDecoder.setNextProtocol(ipv4ProtocolType);
    mockIPv4Decoder.setNextProtocol(tcpProtocolType);

    const decoded = decodePacket(rawPacket, ethLinkType, registry, new Date(), 8, 8);

    expect(decoded.layers.length).toBe(3);
    expect(decoded.layers[0].protocolName).toBe('MockEthernet');
    expect(((decoded.layers[0] as PacketStructureLayer).data as MockEthernetLayerData).type).toBe(
      ipv4ProtocolType,
    );
    expect((decoded.layers[0] as PacketStructureLayer).payload?.toString('hex')).toBe(
      '030405060708',
    );

    expect(decoded.layers[1].protocolName).toBe('MockIPv4');
    expect(((decoded.layers[1] as PacketStructureLayer).data as MockIPv4LayerData).protocol).toBe(
      tcpProtocolType,
    );
    expect((decoded.layers[1] as PacketStructureLayer).payload?.toString('hex')).toBe('05060708');

    expect(decoded.layers[2].protocolName).toBe('MockTCP');
    expect((decoded.layers[2] as PacketStructureLayer).payload?.toString('hex')).toBe('0708'); // TCP mock keeps payload
  });

  it('should handle packets where the decoding chain completes successfully with no remaining payload', () => {
    const rawPacket = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // Eth(2) + IPv4(2) + TCP(2)
    mockEthernetDecoder.setNextProtocol(ipv4ProtocolType);
    mockIPv4Decoder.setNextProtocol(tcpProtocolType);
    // MockTCPDecoder's decode will set payload to undefined if input payload is empty after its header
    const mockTcpNoPayload = new MockTCPDecoder();
    mockTcpNoPayload.decode = (
      buffer: Buffer,
      _context?: unknown,
    ): DecoderOutputLayer<MockTCPLayerData> | null => {
      if (buffer.length < mockTcpNoPayload.headerLength) return null;
      // const header = buffer.subarray(0, mockTcpNoPayload.headerLength);
      // const payload = buffer.subarray(mockTcpNoPayload.headerLength); // No payload beyond TCP header
      return {
        protocolName: mockTcpNoPayload.protocolName,
        headerLength: mockTcpNoPayload.headerLength,
        data: { sourcePort: 1234, destPort: 80 },
        payload: Buffer.alloc(0), // Explicitly no payload
      };
    };
    registry.registerDecoder(tcpProtocolType, mockTcpNoPayload);

    const decoded = decodePacket(rawPacket, ethLinkType, registry);

    expect(decoded.layers.length).toBe(3);
    expect(decoded.layers[0].protocolName).toBe('MockEthernet');
    expect(decoded.layers[1].protocolName).toBe('MockIPv4');
    expect(decoded.layers[2].protocolName).toBe('MockTCP');
    expect((decoded.layers[2] as PacketStructureLayer).payload?.length).toBe(0);
    expect(logger.logWarning).not.toHaveBeenCalled();
  });

  it('should handle unknown protocols within the chain and include remaining data as raw payload', () => {
    const rawPacket = Buffer.from([0x01, 0x02, 0xaa, 0xbb, 0xcc, 0xdd]); // Eth(2) + Unknown(4)
    mockEthernetDecoder.setNextProtocol(unknownProtocolType); // Ethernet points to an unknown protocol

    const decoded = decodePacket(rawPacket, ethLinkType, registry);

    expect(decoded.layers.length).toBe(2); // Ethernet + Raw Data
    expect(decoded.layers[0].protocolName).toBe('MockEthernet');
    expect(((decoded.layers[0] as PacketStructureLayer).data as MockEthernetLayerData).type).toBe(
      unknownProtocolType,
    );
    expect((decoded.layers[0] as PacketStructureLayer).payload?.toString('hex')).toBe('aabbccdd');

    expect(decoded.layers[1].protocolName).toBe('Raw Data');
    expect((decoded.layers[1] as RawPayloadLayer).bytes.toString('hex')).toBe('aabbccdd');
    expect(logger.logWarning).toHaveBeenCalledWith(
      expect.stringContaining(`No decoder found for protocol type: ${unknownProtocolType}`),
    );
  });

  it('should handle error when a decoder throws an exception and include remaining data as raw payload', () => {
    const rawPacket = Buffer.from([0x01, 0x02, 0xee, 0xff, 0x11, 0x22]); // Eth(2) + ErrorDecoderInput(2) + Remaining(2)
    mockEthernetDecoder.setNextProtocol(errorProtocolType); // Ethernet points to ErrorDecoder

    const decoded = decodePacket(rawPacket, ethLinkType, registry);

    expect(decoded.layers.length).toBe(2); // Ethernet + Raw Data (after error)
    expect(decoded.layers[0].protocolName).toBe('MockEthernet');
    expect((decoded.layers[0] as PacketStructureLayer).payload?.toString('hex')).toBe('eeff1122'); // Payload passed to error decoder

    expect(decoded.layers[1].protocolName).toBe('Raw Data');
    // The raw data should be what was passed to the failing decoder
    expect((decoded.layers[1] as RawPayloadLayer).bytes.toString('hex')).toBe('eeff1122');

    expect(logger.logWarning).toHaveBeenCalledWith(
      expect.stringContaining(
        // Updated to check for the generic error message format
        `Unexpected error in protocol ${mockErrorDecoder.protocolName || errorProtocolType}: Mock decoding error`,
      ),
    );
  });

  it('should handle PcapError when a decoder throws a PcapError subclass and include remaining data as raw payload', () => {
    const rawPacket = Buffer.from([0x01, 0x02, 0xdd, 0xcc, 0x33, 0x44]); // Eth(2) + PcapErrorDecoderInput(2) + Remaining(2)
    mockEthernetDecoder.setNextProtocol(pcapErrorProtocolType); // Ethernet points to PcapErrorDecoder

    const decoded = decodePacket(rawPacket, ethLinkType, registry);

    expect(decoded.layers.length).toBe(2); // Ethernet + Raw Data (after PcapError)
    expect(decoded.layers[0].protocolName).toBe('MockEthernet');
    expect((decoded.layers[0] as PacketStructureLayer).payload?.toString('hex')).toBe('ddcc3344');

    expect(decoded.layers[1].protocolName).toBe('Raw Data');
    expect((decoded.layers[1] as RawPayloadLayer).bytes.toString('hex')).toBe('ddcc3344');

    expect(logger.logWarning).toHaveBeenCalledWith(
      expect.stringContaining(
        `Error decoding protocol ${mockPcapErrorDecoder.protocolName || pcapErrorProtocolType} at current stage: Mock PcapDecodingError`,
      ),
    );
  });

  it('should correctly populate DecodedPacket structure with metadata and layer data', () => {
    const rawPacket = Buffer.from([0x01, 0x02, 0x03, 0x04]); // Eth(2) + IPv4(2)
    const timestamp = new Date();
    const originalLength = 100;
    const capturedLength = 4;
    const interfaceInfo = { id: 1, name: 'eth0' };

    mockEthernetDecoder.setNextProtocol(ipv4ProtocolType);
    mockIPv4Decoder.setNextProtocol(null); // IPv4 is the last layer for this test

    const decoded = decodePacket(
      rawPacket,
      ethLinkType,
      registry,
      timestamp,
      originalLength,
      capturedLength,
      interfaceInfo,
    );

    expect(decoded.timestamp).toBe(timestamp);
    expect(decoded.originalLength).toBe(originalLength);
    expect(decoded.capturedLength).toBe(capturedLength);
    expect(decoded.interfaceInfo).toEqual(interfaceInfo);

    expect(decoded.layers.length).toBe(2);
    expect(decoded.layers[0].protocolName).toBe('MockEthernet');
    expect((decoded.layers[0] as PacketStructureLayer).bytes.toString('hex')).toBe('0102');
    expect(decoded.layers[1].protocolName).toBe('MockIPv4');
    expect((decoded.layers[1] as PacketStructureLayer).bytes.toString('hex')).toBe('0304');
    expect((decoded.layers[1] as PacketStructureLayer).payload?.length).toBe(0);
  });

  it('should add remaining data as RawPayloadLayer if loop finishes with data but no next decoder', () => {
    const rawPacket = Buffer.from([0x01, 0x02, 0x03, 0x04, 0xff, 0xee]); // Eth(2) + IPv4(2) + TrailingData(2)
    mockEthernetDecoder.setNextProtocol(ipv4ProtocolType);
    mockIPv4Decoder.setNextProtocol(null); // IPv4 decoder indicates no further protocol

    const decoded = decodePacket(rawPacket, ethLinkType, registry);

    expect(decoded.layers.length).toBe(3); // Eth, IPv4, RawData
    expect(decoded.layers[0].protocolName).toBe('MockEthernet');
    expect(decoded.layers[1].protocolName).toBe('MockIPv4');
    expect((decoded.layers[1] as PacketStructureLayer).payload?.toString('hex')).toBe('ffee'); // Payload from IPv4
    expect(decoded.layers[2].protocolName).toBe('Raw Data');
    expect((decoded.layers[2] as RawPayloadLayer).bytes.toString('hex')).toBe('ffee');
  });

  it('should handle a decoder returning null (cannot decode) and treat remaining as raw', () => {
    const rawPacket = Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // Eth(2) + "Bad" IPv4 data(4)
    mockEthernetDecoder.setNextProtocol(ipv4ProtocolType);

    // Configure IPv4 decoder to fail (return null)
    mockIPv4Decoder.decode = (
      _buffer: Buffer,
      _context?: unknown,
    ): DecoderOutputLayer<MockIPv4LayerData> | null => {
      return null;
    };

    const decoded = decodePacket(rawPacket, ethLinkType, registry);

    expect(decoded.layers.length).toBe(2); // Ethernet + Raw Data
    expect(decoded.layers[0].protocolName).toBe('MockEthernet');
    expect((decoded.layers[0] as PacketStructureLayer).payload?.toString('hex')).toBe('03040506');

    expect(decoded.layers[1].protocolName).toBe('Raw Data');
    expect((decoded.layers[1] as RawPayloadLayer).bytes.toString('hex')).toBe('03040506');
    expect(logger.logWarning).toHaveBeenCalledWith(
      expect.stringContaining(`Decoder for ${mockIPv4Decoder.protocolName} returned null`),
    );
  });

  it('should handle an empty raw packet gracefully', () => {
    const rawPacket = Buffer.from([]);
    const decoded = decodePacket(rawPacket, ethLinkType, registry);

    expect(decoded.layers.length).toBe(0); // No layers if no data
    expect(decoded.originalLength).toBe(0);
    expect(decoded.capturedLength).toBe(0);
    expect(logger.logWarning).not.toHaveBeenCalled();
    expect(logger.logError).not.toHaveBeenCalled();
  });

  it('should handle a packet where the first decoder is not found', () => {
    const rawPacket = Buffer.from([0x01, 0x02, 0x03, 0x04]);
    const nonExistentLinkType = 999;
    const decoded = decodePacket(rawPacket, nonExistentLinkType, registry);

    expect(decoded.layers.length).toBe(1); // Only Raw Data layer
    expect(decoded.layers[0].protocolName).toBe('Raw Data');
    expect((decoded.layers[0] as RawPayloadLayer).bytes.toString('hex')).toBe('01020304');
    expect(logger.logWarning).toHaveBeenCalledWith(
      expect.stringContaining(`No decoder found for protocol type: ${nonExistentLinkType}`),
    );
  });
});
