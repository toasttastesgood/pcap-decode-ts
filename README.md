# pcap-decoder-ts

`pcap-decoder-ts` is a TypeScript library for parsing and decoding network packet captures stored in PCAP ( `.pcap` ) and PCAPng ( `.pcapng` ) file formats. It provides a flexible and extensible way to analyze network traffic, with built-in decoders for common protocols and an API for adding custom decoders.

## Features

- **PCAP and PCAPng Support**: Parses both widely-used packet capture formats.
- **Layered Decoding**: Decodes packets layer by layer (e.g., Ethernet -> IP -> TCP -> HTTP).
- **Extensible Decoder Registry**: Allows users to register custom decoders for proprietary or unsupported protocols.
- **Type-Safe**: Written in TypeScript, providing strong typing for decoded packet structures.
- **Asynchronous Iteration**: Provides async iterators for efficiently processing large capture files.
- **Comprehensive Error Handling**: Clear error types for parsing and decoding issues.
- **Utility Functions**: Includes helpers for formatting IP addresses, MAC addresses, and reading multi-byte numbers from buffers.

## Installation

To install `pcap-decoder-ts` in your project, use npm or yarn:

```bash
npm install pcap-decoder-ts
```

or

```bash
yarn add pcap-decoder-ts
```

_(Note: This assumes the package will be published as `pcap-decoder-ts` on npm.)_

## Quick Start

Here's a simple example of how to use the library to read packets from a PCAP file buffer and log decoded information:

```typescript
import { promises as fs } from 'fs';
import {
  iteratePcapPackets,
  decodePacket,
  DecoderRegistry,
  Ethernet2Decoder,
  IPv4Decoder,
  TCPDecoder,
  UDPDecoder,
  ARPDecoder,
  ICMPv4Decoder,
  ICMPv6Decoder,
  DNSDecoder,
  HTTP1Decoder,
} from 'pcap-decoder-ts'; // Adjust path if using locally

async function main() {
  try {
    // 1. Read the PCAP file into a buffer
    const pcapBuffer = await fs.readFile('path/to/your/capture.pcap');

    // 2. Create a decoder registry and register some common decoders
    const registry = new DecoderRegistry();
    registry.registerDecoder(1, new Ethernet2Decoder()); // LINKTYPE_ETHERNET
    registry.registerDecoder(0x0800, new IPv4Decoder(), 10); // EtherType for IPv4, higher priority
    registry.registerDecoder(0x0806, new ARPDecoder(), 10); // EtherType for ARP
    registry.registerDecoder(0x86dd, new IPv6Decoder(), 10); // EtherType for IPv6

    registry.registerDecoder(1, new ICMPv4Decoder(), 20); // IP Protocol for ICMPv4
    registry.registerDecoder(6, new TCPDecoder(), 20); // IP Protocol for TCP
    registry.registerDecoder(17, new UDPDecoder(), 20); // IP Protocol for UDP
    registry.registerDecoder(58, new ICMPv6Decoder(), 20); // IP Protocol for ICMPv6

    // Application layer decoders (usually registered based on port numbers or other context)
    // For simplicity, we'll register DNS for UDP port 53 and HTTP for TCP port 80
    // In a real scenario, you might register these dynamically or have a more complex setup.
    // Note: The current DecoderRegistry uses protocol IDs directly. Port-based registration
    // would typically be handled by the transport layer decoder (TCP/UDP) invoking specific
    // application decoders based on port numbers. This example simplifies that.
    // A more robust approach would be for TCP/UDP decoders to use a sub-registry or context.

    // For demonstration, let's assume DNS and HTTP decoders are directly triggered by their transport.
    // This part of the example is illustrative of using the decoders, actual registration
    // for application protocols often depends on transport layer context.
    // For now, we'll assume a mechanism where they could be invoked.
    // A common pattern is for TCP/UDP decoders to look up application decoders based on ports.

    // 3. Iterate over packets
    for await (const pcapPacket of iteratePcapPackets(pcapBuffer)) {
      console.log(`\n--- New PCAP Packet ---`);
      console.log(
        `Timestamp: ${new Date(pcapPacket.header.ts_sec * 1000 + pcapPacket.header.ts_usec / 1000).toISOString()}`,
      );
      console.log(
        `Captured Length: ${pcapPacket.header.incl_len}, Original Length: ${pcapPacket.header.orig_len}`,
      );

      // 4. Decode the packet data
      // Assuming LINKTYPE_ETHERNET (1) from the PCAP global header
      const decodedPacket = decodePacket(
        pcapPacket.packetData,
        1, // Link Layer Type (e.g., 1 for Ethernet from PCAP global header)
        registry,
        new Date(pcapPacket.header.ts_sec * 1000 + pcapPacket.header.ts_usec / 1000),
        pcapPacket.header.orig_len,
        pcapPacket.header.incl_len,
      );

      console.log('Decoded Layers:');
      decodedPacket.layers.forEach((layer, index) => {
        console.log(`  Layer ${index + 1}: ${layer.protocolName}`);
        // console.log(  `    Data:`, layer.data); // Can be verbose
        if (
          (layer.protocolName === 'TCP' && layer.data?.destinationPort === 80) ||
          layer.data?.sourcePort === 80
        ) {
          const httpDecoder = new HTTP1Decoder();
          const httpLayer = httpDecoder.decode(layer.payload as Buffer);
          if (httpLayer) {
            console.log(`    HTTP Details:`, httpLayer.data);
          }
        }
        if (
          (layer.protocolName === 'UDP' && layer.data?.destinationPort === 53) ||
          layer.data?.sourcePort === 53
        ) {
          const dnsDecoder = new DNSDecoder();
          const dnsLayer = dnsDecoder.decode(layer.payload as Buffer);
          if (dnsLayer) {
            console.log(`    DNS Details:`, dnsLayer.data);
          }
        }
      });
    }
  } catch (error) {
    console.error('Error processing PCAP file:', error);
  }
}

main();
```

_(Note: The example above assumes the PCAP file uses Ethernet (Linktype 1). For PCAPng files, use `iteratePcapNgPackets` and the linktype from the Interface Description Block.)_

## API Documentation

Detailed API documentation generated from TSDoc comments can be found here:

[API Reference](./docs/api/index.html)

## Extensibility

`pcap-decoder-ts` is designed to be extensible. You can create and register your own decoders to support additional protocols or to customize the decoding behavior for existing ones.

For more details on how to implement and use custom decoders, please refer to the [Extensibility Guide](./docs/extensibility.md).

## Contributing

Contributions are welcome! Please refer to the development plan and open issues for areas where help is needed.

## License

This project is licensed under the ISC License. See the LICENSE file for details.
