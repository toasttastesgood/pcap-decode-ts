import { expect, test, describe } from 'vitest';
import * as pcapDecoder from '../index';

describe('pcap-decoder-ts basic exports', () => {
  test('should export error classes', () => {
    expect(pcapDecoder.PcapError).toBeDefined();
    expect(pcapDecoder.PcapParsingError).toBeDefined(); // Corrected from PcapNgError
    expect(pcapDecoder.PcapDecodingError).toBeDefined(); // Corrected from DecodingError
    expect(pcapDecoder.InvalidFileFormatError).toBeDefined();
    expect(pcapDecoder.BufferOutOfBoundsError).toBeDefined();
    // PcapDecodingError is already checked above
  });

  test('should export PCAP parsing functions and interfaces', () => {
    expect(pcapDecoder.iteratePcapPackets).toBeInstanceOf(Function);
    expect(pcapDecoder.parsePcapGlobalHeader).toBeInstanceOf(Function);
    expect(pcapDecoder.parsePcapPacketRecord).toBeInstanceOf(Function);
    // Interfaces are not directly testable for existence at runtime like this,
    // but their related classes/functions being exported is a good sign.
    // e.g. PcapGlobalHeader, PcapPacketRecordHeader, PcapPacket
  });

  test('should export PCAPng parsing functions and interfaces', () => {
    expect(pcapDecoder.iteratePcapNgPackets).toBeInstanceOf(Function);
    expect(pcapDecoder.parseSectionHeaderBlock).toBeInstanceOf(Function);
    expect(pcapDecoder.parseInterfaceDescriptionBlock).toBeInstanceOf(Function);
    expect(pcapDecoder.parseEnhancedPacketBlock).toBeInstanceOf(Function);
    expect(pcapDecoder.parseNameResolutionBlock).toBeInstanceOf(Function);
    expect(pcapDecoder.parsePcapNgGenericBlock).toBeInstanceOf(Function);
    // e.g. PcapNgBlockType, PcapNgSectionHeaderBlock, PcapNgPacket
  });

  test('should export core decoding components', () => {
    expect(pcapDecoder.decodePacket).toBeInstanceOf(Function);
    expect(pcapDecoder.DecoderRegistry).toBeInstanceOf(Function); // Class
    // e.g. Decoder, DecodedPacket, PacketLayer
  });

  test('should export specific protocol decoders and layers', () => {
    expect(pcapDecoder.Ethernet2Decoder).toBeInstanceOf(Function);
    expect(pcapDecoder.IPv4Decoder).toBeInstanceOf(Function);
    expect(pcapDecoder.IPv6Decoder).toBeInstanceOf(Function);
    expect(pcapDecoder.ARPDecoder).toBeInstanceOf(Function);
    expect(pcapDecoder.TCPDecoder).toBeInstanceOf(Function);
    expect(pcapDecoder.UDPDecoder).toBeInstanceOf(Function);
    expect(pcapDecoder.ICMPv4Decoder).toBeInstanceOf(Function);
    expect(pcapDecoder.ICMPv6Decoder).toBeInstanceOf(Function);
    expect(pcapDecoder.DNSDecoder).toBeInstanceOf(Function);
    expect(pcapDecoder.HTTP1Decoder).toBeInstanceOf(Function);

    // Check for a few layer interfaces (presence implies export)
    // TypeScript interfaces are compile-time constructs, so we can't directly check them at runtime.
    // However, if code using them compiles, it's a good sign.
    // For basic.test.ts, confirming the decoders are exported is the primary goal.
    // Example: If IPv4Layer was not exported, using it in type hints would fail at compile time.
  });

  test('should export ICMPv6Layer related types', () => {
    // Verifying that ICMPv6Layer and its related types are exported.
    // Actual type checking is done by TypeScript compiler, this is a runtime check for existence.
    // We can't directly check for `ICMPv6Layer` interface, but we can check for related concrete exports if any,
    // or rely on the fact that `ICMPv6Decoder` which uses `ICMPv6Layer` is exported.
    // The export `export * from './decode/icmpv6/icmpv6-layer';` should make all its exports available.
    // For example, if ICMPv6Option was a class, we could do:
    // expect(pcapDecoder.ICMPv6Option).toBeDefined();
    // Since they are interfaces, their successful use in the codebase (e.g. ICMPv6Decoder) and compilation is the main check.
    // This test serves as a placeholder to acknowledge the check for ICMPv6Layer exports.
    expect(pcapDecoder.ICMPv6Decoder).toBeDefined(); // Relies on ICMPv6Layer
  });


  test('should export utility functions', () => {
    expect(pcapDecoder.readUint8).toBeInstanceOf(Function); // from byte-readers
    expect(pcapDecoder.formatIPv4).toBeInstanceOf(Function);
    expect(pcapDecoder.formatIPv6).toBeInstanceOf(Function);
    expect(pcapDecoder.formatMacAddress).toBeInstanceOf(Function);
    expect(pcapDecoder.setLogLevel).toBeInstanceOf(Function);
    expect(pcapDecoder.getLogLevel).toBeInstanceOf(Function);
    expect(pcapDecoder.logDebug).toBeInstanceOf(Function);
    expect(pcapDecoder.getServiceName).toBeInstanceOf(Function);
  });

  test('should export specific layer interfaces (conceptual check)', () => {
    // This test is more of a conceptual check.
    // TypeScript interfaces are not present at runtime in a way that `toBeDefined` can check.
    // Their correct export is verified by the TypeScript compiler when this test file (and the library itself) is compiled.
    // If `src/index.ts` failed to export `IPv4Layer` (for example), and `IPv4Decoder` used it in its signature,
    // the library would not compile, or dependent code would fail.
    // We are checking that the modules exporting these interfaces are included in `src/index.ts`.
    expect(pcapDecoder.IPv4Decoder).toBeDefined(); // Uses IPv4Layer
    // TCPLayer is an interface, not a runtime value. Its export is verified by successful compilation.
  });
});
