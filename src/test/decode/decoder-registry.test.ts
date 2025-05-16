import { describe, test, beforeEach, expect } from 'vitest';
import { DecoderRegistry } from '../../decode/decoder-registry';
import { Decoder, DecoderOutputLayer } from '../../decode/decoder';

// Mock Decoder implementation for testing
// Using 'any' for TLayerData as it's a generic mock
interface MockLayerData {
  data: string;
  from: string;
}

class MockDecoder implements Decoder<MockLayerData> {
  public protocolName: string;
  private nextType: number | string | null;
  private mockHeaderLength: number;

  constructor(
    name: string = 'mock',
    nextType: number | string | null = null,
    headerLength: number = 10,
  ) {
    this.protocolName = name;
    this.nextType = nextType;
    this.mockHeaderLength = headerLength;
  }

  public decode(buffer: Buffer, context?: unknown): DecoderOutputLayer<MockLayerData> | null {
    // Simple mock decode, doesn't use buffer or context for this test
    return {
      protocolName: this.protocolName,
      headerLength: this.mockHeaderLength,
      data: { data: 'decoded', from: this.protocolName },
      payload: buffer.subarray(this.mockHeaderLength), // Mock payload
      context,
    };
  }

  public nextProtocolType(_decodedLayer: MockLayerData): number | string | null {
    return this.nextType;
  }
}

describe('DecoderRegistry', () => {
  let registry: DecoderRegistry;
  const mockDecoder1 = new MockDecoder('mock1');
  const mockDecoder2 = new MockDecoder('mock2');
  const mockDecoder3 = new MockDecoder('mock3');

  beforeEach(() => {
    registry = new DecoderRegistry();
  });

  test('should register and retrieve a decoder', () => {
    registry.registerDecoder(1, mockDecoder1);
    const decoder = registry.getDecoder(1);
    expect(decoder).toBe(mockDecoder1);
  });

  test('should register and retrieve a decoder with string ID', () => {
    registry.registerDecoder('ethertype-ip', mockDecoder1);
    const decoder = registry.getDecoder('ethertype-ip');
    expect(decoder).toBe(mockDecoder1);
  });

  test('should return undefined for an unregistered decoder', () => {
    const decoder = registry.getDecoder(999);
    expect(decoder).toBeUndefined();
  });

  test('should return undefined for an unregistered string ID decoder', () => {
    const decoder = registry.getDecoder('unknown-protocol');
    expect(decoder).toBeUndefined();
  });

  test('should use default priority 0 if not specified', () => {
    registry.registerDecoder(2, mockDecoder1); // priority 0
    registry.registerDecoder(2, mockDecoder2, 1); // priority 1
    const decoder = registry.getDecoder(2);
    expect(decoder).toBe(mockDecoder1);
  });

  test('should retrieve the decoder with the highest priority (lowest number)', () => {
    registry.registerDecoder(3, mockDecoder1, 10);
    registry.registerDecoder(3, mockDecoder2, 0); // Highest priority
    registry.registerDecoder(3, mockDecoder3, 5);
    const decoder = registry.getDecoder(3);
    expect(decoder).toBe(mockDecoder2);
  });

  test('should retrieve the decoder with the highest priority when priorities are negative', () => {
    registry.registerDecoder(4, mockDecoder1, 0);
    registry.registerDecoder(4, mockDecoder2, -5); // Highest priority
    registry.registerDecoder(4, mockDecoder3, -1);
    const decoder = registry.getDecoder(4);
    expect(decoder).toBe(mockDecoder2);
  });

  test('should handle multiple decoders for different IDs', () => {
    registry.registerDecoder(5, mockDecoder1);
    registry.registerDecoder(6, mockDecoder2);
    expect(registry.getDecoder(5)).toBe(mockDecoder1);
    expect(registry.getDecoder(6)).toBe(mockDecoder2);
  });

  test('should overwrite with the same priority (last one registered wins if priorities are equal and it is added later to the list, but sorting is stable)', () => {
    // The current implementation's sort is stable, but if two have the same priority,
    // the order they were pushed might matter if the sort wasn't stable.
    // Given Array.prototype.sort is not guaranteed stable by ECMA spec but often is in practice,
    // this test confirms the behavior with the current implementation.
    // If a new decoder with the same highest priority is added, it should not displace the existing one
    // unless it's explicitly a higher priority (lower number).
    // If they have the exact same priority, the first one registered with that priority should be kept.
    registry.registerDecoder(7, mockDecoder1, 0);
    registry.registerDecoder(7, mockDecoder2, 0); // Same priority
    const decoder = registry.getDecoder(7);
    // The sort places mockDecoder1 first, then mockDecoder2.
    // So, mockDecoder1 should be returned.
    expect(decoder).toBe(mockDecoder1);

    const registry2 = new DecoderRegistry();
    registry2.registerDecoder(8, mockDecoder2, 0);
    registry2.registerDecoder(8, mockDecoder1, 0);
    const decoder2 = registry2.getDecoder(8);
    expect(decoder2).toBe(mockDecoder2); // mockDecoder2 was registered first with priority 0
  });

  test('should return the correct decoder when priorities are the same but registration order differs', () => {
    registry.registerDecoder(10, mockDecoder1, 1);
    registry.registerDecoder(10, mockDecoder2, 0); // mockDecoder2 is higher priority
    registry.registerDecoder(10, mockDecoder3, 1); // mockDecoder3 has same priority as mockDecoder1

    // mockDecoder2 should be returned as it has the highest priority (0)
    expect(registry.getDecoder(10)).toBe(mockDecoder2);

    // Test with a new registry to ensure clean state
    const newRegistry = new DecoderRegistry();
    newRegistry.registerDecoder(11, mockDecoder3, 1);
    newRegistry.registerDecoder(11, mockDecoder1, 1);
    newRegistry.registerDecoder(11, mockDecoder2, 0); // mockDecoder2 is higher priority

    expect(newRegistry.getDecoder(11)).toBe(mockDecoder2);
  });

  test('registering a decoder with an existing ID and higher priority updates correctly', () => {
    registry.registerDecoder(12, mockDecoder1, 10);
    expect(registry.getDecoder(12)).toBe(mockDecoder1);

    registry.registerDecoder(12, mockDecoder2, 5); // Higher priority
    expect(registry.getDecoder(12)).toBe(mockDecoder2);

    registry.registerDecoder(12, mockDecoder3, 0); // Even higher priority
    expect(registry.getDecoder(12)).toBe(mockDecoder3);
  });

  test('registering a decoder with an existing ID and lower priority does not change the result', () => {
    registry.registerDecoder(13, mockDecoder1, 0);
    expect(registry.getDecoder(13)).toBe(mockDecoder1);

    registry.registerDecoder(13, mockDecoder2, 5); // Lower priority
    expect(registry.getDecoder(13)).toBe(mockDecoder1);
  });
});
