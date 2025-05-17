import * as fs from 'fs';
import * as path from 'path';
import { Buffer } from 'buffer';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'; // Added vi, beforeEach, afterEach

import { iteratePcapPackets } from '../../pcap/pcap-iterator';
import { parsePcapGlobalHeader } from '../../pcap/global-header-parser'; // Added
import { iteratePcapNgPackets } from '../../pcapng/pcapng-iterator';
import { decodePacket } from '../../decode/packet-decoder';
import { DecoderRegistry } from '../../decode/decoder-registry';
import { Ethernet2Decoder } from '../../decode/ethernet/ethernet2-decoder';
import { IPv4Decoder } from '../../decode/ipv4/ipv4-decoder';
import { IPv6Decoder } from '../../decode/ipv6/ipv6-decoder';
import { ARPDecoder } from '../../decode/arp/arp-decoder';
import { ICMPv4Decoder } from '../../decode/icmpv4/icmpv4-decoder';
import { ICMPv6Decoder } from '../../decode/icmpv6/icmpv6-decoder';
import { TCPDecoder } from '../../decode/tcp/tcp-decoder';
import { UDPDecoder } from '../../decode/udp/udp-decoder';
import { DNSDecoder } from '../../decode/dns/dns-decoder';
import { HTTP1Decoder } from '../../decode/http/http1-decoder';
import type {
  DecodedPacket,
  DecodedPacketLayer,
} from '../../decode/packet-structures';
import type { Ethernet2Layer } from '../../decode/ethernet/ethernet2-decoder'; // Assuming exported from decoder
import type { IPv4Layer } from '../../decode/ipv4/ipv4-layer';
import type { TCPLayer } from '../../decode/tcp/tcp-layer';
import type { UDPLayer } from '../../decode/udp/udp-decoder'; // Assuming exported from decoder
import type { DNSLayer } from '../../decode/dns/dns-layer';
  // ARPLayer, // Import if/when an ARP-specific test is added
  // IPv6Layer, // Import if/when an IPv6-specific test is added
  // ICMPv4Layer, // Import if/when an ICMPv4-specific test is added
  // ICMPv6Layer, // Import if/when an ICMPv6-specific test is added

const dataDir = path.join(__dirname, '..', '..', 'test', 'data');

describe('End-to-End Packet Decoding', () => {
  const decoderRegistry = new DecoderRegistry();
  // Link Layer Type
  decoderRegistry.registerDecoder(1, new Ethernet2Decoder()); // LINKTYPE_ETHERNET

  // EtherTypes (used by Ethernet2Decoder.nextProtocolType)
  decoderRegistry.registerDecoder(0x0800, new IPv4Decoder()); // ETHERTYPE_IPV4
  decoderRegistry.registerDecoder(0x0806, new ARPDecoder()); // ETHERTYPE_ARP
  decoderRegistry.registerDecoder(0x86dd, new IPv6Decoder()); // ETHERTYPE_IPV6

  // IP Protocol Numbers (used by IPv4Decoder.nextProtocolType and IPv6Decoder.nextProtocolType)
  decoderRegistry.registerDecoder(1, new ICMPv4Decoder()); // IPPROTO_ICMP
  decoderRegistry.registerDecoder(58, new ICMPv6Decoder()); // IPPROTO_ICMPV6
  decoderRegistry.registerDecoder(6, new TCPDecoder()); // IPPROTO_TCP
  decoderRegistry.registerDecoder(17, new UDPDecoder()); // IPPROTO_UDP

  // Application Layer (assuming TCP/UDP decoders return these string identifiers or specific ports)
  decoderRegistry.registerDecoder('DNS', new DNSDecoder()); // Or specific ports if returned by UDP/TCP
  decoderRegistry.registerDecoder('HTTP', new HTTP1Decoder()); // Or specific ports if returned by TCP

  describe('PCAP File Decoding', () => {
    it('should decode packets from dns.cap correctly', async () => {
      const filePath = path.join(dataDir, 'dns.cap');
      const fileBuffer = fs.readFileSync(filePath);
      const globalHeader = parsePcapGlobalHeader(fileBuffer);
      if (!globalHeader) throw new Error('Could not parse PCAP global header for dns.cap');
      expect(globalHeader.network).toBe(1); // LINKTYPE_ETHERNET

      for await (const packetData of iteratePcapPackets(fileBuffer)) {
        const timestamp = packetData.header.ts_sec + packetData.header.ts_usec / 1_000_000;
        const decodedPacket: DecodedPacket = decodePacket(
          packetData.packetData,
          globalHeader.network, // initialLinkLayerType
          decoderRegistry,
          timestamp,
          packetData.header.orig_len,
          packetData.header.incl_len,
        );

        expect(decodedPacket).toBeDefined();
        expect(decodedPacket.timestamp).toBe(timestamp);
        expect(decodedPacket.originalLength).toBe(packetData.header.orig_len);
        expect(decodedPacket.capturedLength).toBe(packetData.header.incl_len);
        expect(decodedPacket.layers).toBeInstanceOf(Array);
        expect(decodedPacket.layers.length).toBeGreaterThan(0);

        for (const layer of decodedPacket.layers) {
          expect(layer).toHaveProperty('protocolName');
          expect(layer).toHaveProperty('bytes');
          expect(layer.bytes).toBeInstanceOf(Buffer);
          expect(layer.bytes.length).toBeGreaterThan(0);

          if (layer.protocolName !== 'Raw Data') {
            const decodedLayer = layer as DecodedPacketLayer;
            expect(decodedLayer).toHaveProperty('data');
            // Payload is optional, so check if it exists before asserting its type
            if (Object.prototype.hasOwnProperty.call(decodedLayer, 'payload')) {
              expect(decodedLayer.payload).toBeInstanceOf(Buffer);
            }
          }
        }

        // Example: Assertions for a typical DNS query packet structure
        // This requires knowledge of the specific dns.cap content.
        // For now, we'll check if there are at least 3 layers (e.g., Eth, IP, UDP/TCP)
        // and if the last one could be DNS or Raw Data if DNS parsing fails.
        // Assuming dns.cap contains Ethernet -> IPv4 -> UDP -> DNS packets
        if (decodedPacket.layers.length >= 3) {
          const ethLayerObject = decodedPacket.layers[0];
          expect(ethLayerObject.protocolName).toBe('Ethernet II');

          const ipLayerObject = decodedPacket.layers[1];
          expect(ipLayerObject.protocolName).toBe('IPv4');
          if (ipLayerObject.protocolName === 'IPv4') {
            const ipData = (ipLayerObject as DecodedPacketLayer).data as IPv4Layer;
            // Example: expect(ipData.sourceAddress).toBe('192.168.1.100'); // If known
          }

          const transportLayerObject = decodedPacket.layers[2];
          expect(transportLayerObject.protocolName).toBe('UDP');
          if (transportLayerObject.protocolName === 'UDP') {
            const udpData = (transportLayerObject as DecodedPacketLayer).data as UDPLayer;
            // Example: expect(udpData.destinationPort).toBe(53); // If known
          }

          if (decodedPacket.layers.length >= 4) {
            const appLayerObject = decodedPacket.layers[3];
            expect(appLayerObject.protocolName).toBe('DNS');
            if (appLayerObject.protocolName === 'DNS') {
              const dnsData = (appLayerObject as DecodedPacketLayer).data as DNSLayer;
              // Example: expect(dnsData.queries?.[0]?.name).toBe('example.com'); // If known
            }

            // Check raw bytes and payload consistency
            const ethPayload = (ethLayerObject as DecodedPacketLayer).payload;
            if (ethLayerObject.protocolName === 'Ethernet II' && ethPayload) {
              expect(
                ipLayerObject.bytes.equals(ethPayload.subarray(0, ipLayerObject.bytes.length)),
              ).toBe(true);
            }

            const ipPayload = (ipLayerObject as DecodedPacketLayer).payload;
            if (ipLayerObject.protocolName === 'IPv4' && ipPayload) {
              expect(
                transportLayerObject.bytes.equals(ipPayload.subarray(0, transportLayerObject.bytes.length)),
              ).toBe(true);
            }

            const transportPayload = (transportLayerObject as DecodedPacketLayer).payload;
            if (transportLayerObject.protocolName === 'UDP' && transportPayload && appLayerObject.protocolName === 'DNS') {
              expect(
                appLayerObject.bytes.equals(
                  transportPayload.subarray(0, appLayerObject.bytes.length),
                ),
              ).toBe(true);
            }
          }
        }
      }
    });

    it('should decode packets from ipv4frags.pcap correctly', async () => {
      const filePath = path.join(dataDir, 'ipv4frags.pcap');
      const fileBuffer = fs.readFileSync(filePath);
      const globalHeader = parsePcapGlobalHeader(fileBuffer);
      if (!globalHeader) throw new Error('Could not parse PCAP global header for ipv4frags.pcap');
      expect(globalHeader.network).toBe(1); // LINKTYPE_ETHERNET

      for await (const packetData of iteratePcapPackets(fileBuffer)) {
        const timestamp = packetData.header.ts_sec + packetData.header.ts_usec / 1_000_000;
        const decodedPacket: DecodedPacket = decodePacket(
          packetData.packetData,
          globalHeader.network,
          decoderRegistry,
          timestamp,
          packetData.header.orig_len,
          packetData.header.incl_len,
        );

        expect(decodedPacket).toBeDefined();
        expect(decodedPacket.layers.length).toBeGreaterThan(0);
        const ethLayerObject = decodedPacket.layers[0];
        expect(ethLayerObject.protocolName).toBe('Ethernet II');

        if (decodedPacket.layers.length > 1) {
          const ipLayerObject = decodedPacket.layers[1];
          expect(ipLayerObject.protocolName).toBe('IPv4');
          if (ipLayerObject.protocolName === 'IPv4') {
            const ipData = (ipLayerObject as DecodedPacketLayer).data as IPv4Layer;
            // Check for fragmentation indicators
            // Example: if (ipData.flags && (ipData.flags.mf || ipData.fragmentOffset > 0)) { /* is fragmented */ }
            const ipPayload = (ipLayerObject as DecodedPacketLayer).payload;
            if (ipPayload && ipPayload.length > 0) {
              // If it's not the last fragment, it might not have a recognized L4 protocol
              // or it might be 'Raw Data' if the payload is part of a fragment.
            }
          }
        }
      }
    });

    it('should decode TCP packets from chargen-tcp.pcap correctly', async () => {
      const filePath = path.join(dataDir, 'chargen-tcp.pcap');
      const fileBuffer = fs.readFileSync(filePath);
      const globalHeader = parsePcapGlobalHeader(fileBuffer);
      if (!globalHeader) throw new Error('Could not parse PCAP global header for chargen-tcp.pcap');
      expect(globalHeader.network).toBe(1); // LINKTYPE_ETHERNET

      for await (const packetData of iteratePcapPackets(fileBuffer)) {
        const timestamp = packetData.header.ts_sec + packetData.header.ts_usec / 1_000_000;
        const decodedPacket: DecodedPacket = decodePacket(
          packetData.packetData,
          globalHeader.network,
          decoderRegistry,
          timestamp,
          packetData.header.orig_len,
          packetData.header.incl_len,
        );

        expect(decodedPacket).toBeDefined();
        expect(decodedPacket.layers.length).toBeGreaterThanOrEqual(3); // Eth, IP, TCP
        const ethLayerObject = decodedPacket.layers[0];
        expect(ethLayerObject.protocolName).toBe('Ethernet II');
        const ipLayerObject = decodedPacket.layers[1];
        expect(ipLayerObject.protocolName).toBe('IPv4');
        const tcpLayerObject = decodedPacket.layers[2];
        expect(tcpLayerObject.protocolName).toBe('TCP');

        if (tcpLayerObject.protocolName === 'TCP') {
          const tcpData = (tcpLayerObject as DecodedPacketLayer).data as TCPLayer;
          expect(tcpData).toBeDefined();
          expect(tcpData.sourcePort).toBeGreaterThan(0);
          expect(tcpData.destinationPort).toBeGreaterThan(0);

          const isChargenPort = tcpData.sourcePort === 19 || tcpData.destinationPort === 19;
          if (isChargenPort && decodedPacket.layers.length > 3) {
            const appLayerObject = decodedPacket.layers[3];
            expect(appLayerObject.protocolName).toBe('Raw Data'); // No specific Chargen decoder
            expect(appLayerObject.bytes.length).toBeGreaterThan(0);
          }
        }
      }
    });

    it('should decode UDP packets from chargen-udp.pcap correctly', async () => {
      const filePath = path.join(dataDir, 'chargen-udp.pcap');
      const fileBuffer = fs.readFileSync(filePath);
      const globalHeader = parsePcapGlobalHeader(fileBuffer);
      if (!globalHeader) throw new Error('Could not parse PCAP global header for chargen-udp.pcap');
      expect(globalHeader.network).toBe(1); // LINKTYPE_ETHERNET

      for await (const packetData of iteratePcapPackets(fileBuffer)) {
        const timestamp = packetData.header.ts_sec + packetData.header.ts_usec / 1_000_000;
        const decodedPacket: DecodedPacket = decodePacket(
          packetData.packetData,
          globalHeader.network,
          decoderRegistry,
          timestamp,
          packetData.header.orig_len,
          packetData.header.incl_len,
        );

        expect(decodedPacket).toBeDefined();
        expect(decodedPacket.layers.length).toBeGreaterThanOrEqual(3); // Eth, IP, UDP
        const ethLayerObject = decodedPacket.layers[0];
        expect(ethLayerObject.protocolName).toBe('Ethernet II');
        const ipLayerObject = decodedPacket.layers[1];
        expect(ipLayerObject.protocolName).toBe('IPv4');
        const udpLayerObject = decodedPacket.layers[2];
        expect(udpLayerObject.protocolName).toBe('UDP');

        if (udpLayerObject.protocolName === 'UDP') {
          const udpData = (udpLayerObject as DecodedPacketLayer).data as UDPLayer;
          expect(udpData).toBeDefined();
          expect(udpData.sourcePort).toBeGreaterThan(0);
          expect(udpData.destinationPort).toBeGreaterThan(0);
          expect(udpData.length).toBeGreaterThanOrEqual(8); // UDP header size

          const isChargenPort = udpData.sourcePort === 19 || udpData.destinationPort === 19;
          if (isChargenPort && decodedPacket.layers.length > 3) {
            const appLayerObject = decodedPacket.layers[3];
            expect(appLayerObject.protocolName).toBe('Raw Data'); // No specific Chargen decoder
            expect(appLayerObject.bytes.length).toBeGreaterThan(0);
          }
        }
      }
    });

    it('should decode DHCP packets from dhcp.pcap correctly', async () => {
      const filePath = path.join(dataDir, 'dhcp.pcap');
      const fileBuffer = fs.readFileSync(filePath);
      const globalHeader = parsePcapGlobalHeader(fileBuffer);
      if (!globalHeader) throw new Error('Could not parse PCAP global header for dhcp.pcap');
      expect(globalHeader.network).toBe(1); // LINKTYPE_ETHERNET

      for await (const packetData of iteratePcapPackets(fileBuffer)) {
        const timestamp = packetData.header.ts_sec + packetData.header.ts_usec / 1_000_000;
        const decodedPacket: DecodedPacket = decodePacket(
          packetData.packetData,
          globalHeader.network,
          decoderRegistry,
          timestamp,
          packetData.header.orig_len,
          packetData.header.incl_len,
        );

        expect(decodedPacket).toBeDefined();
        expect(decodedPacket.layers.length).toBeGreaterThanOrEqual(3); // Eth, IP, UDP
        const ethLayerObject = decodedPacket.layers[0];
        expect(ethLayerObject.protocolName).toBe('Ethernet II');
        const ipLayerObject = decodedPacket.layers[1];
        expect(ipLayerObject.protocolName).toBe('IPv4');
        const udpLayerObject = decodedPacket.layers[2];
        expect(udpLayerObject.protocolName).toBe('UDP');

        if (udpLayerObject.protocolName === 'UDP') {
          const udpData = (udpLayerObject as DecodedPacketLayer).data as UDPLayer;
          expect(udpData).toBeDefined();

          const isDhcpPort =
            (udpData.sourcePort === 67 && udpData.destinationPort === 68) ||
            (udpData.sourcePort === 68 && udpData.destinationPort === 67);
          expect(isDhcpPort).toBe(true);

          if (decodedPacket.layers.length > 3) {
            const appLayerObject = decodedPacket.layers[3];
            // No specific DHCP decoder is registered, so it should be Raw Data
            expect(appLayerObject.protocolName).toBe('Raw Data');
            expect(appLayerObject.bytes.length).toBeGreaterThan(0);
          }
        }
      }
    });
    // e.g., it('should decode packets from some_other_file.pcap correctly', () => { ... });
  });

  describe('PCAPng File Decoding', () => {
    it('should decode packets from couchbase-create-bucket.pcapng correctly', async () => {
      const filePath = path.join(dataDir, 'couchbase-create-bucket.pcapng');
      const fileBuffer = fs.readFileSync(filePath);

      for await (const packetData of iteratePcapNgPackets(fileBuffer)) {
        // iteratePcapNgPackets yields PcapNgPacket for EPB blocks.
        // We don't need to check blockType here as the iterator should only yield packet structures.
        // If it yields other block types, the PcapNgPacket interface would be different.
        // Assuming PcapNgPacket is yielded for EnhancedPacketBlock and SimplePacketBlock (if supported by iterator)

        const timestamp = Number(packetData.timestamp) / 1_000_000_000.0; // Convert BigInt ns to number seconds
        const interfaceInfo = {
          interfaceId: packetData.interface_id,
          name: packetData.interface_name,
          description: packetData.interface_description,
          linkType: packetData.interface_link_type,
        };

        const decodedPacket = decodePacket(
          packetData.packetData,
          packetData.interface_link_type,
          decoderRegistry,
          timestamp,
          packetData.originalLength,
          packetData.capturedLength,
          interfaceInfo,
        );

        const decodedPkt = decodedPacket as DecodedPacket; // Use DecodedPacket type
        expect(decodedPkt).toBeDefined();
        expect(decodedPkt.timestamp).toBeCloseTo(timestamp, 9); // Compare with high precision
        expect(decodedPkt.originalLength).toBe(packetData.originalLength);
        expect(decodedPkt.capturedLength).toBe(packetData.capturedLength);
        expect(decodedPkt.layers).toBeInstanceOf(Array);
        expect(decodedPkt.layers.length).toBeGreaterThan(0);
        expect(decodedPkt.interfaceInfo).toEqual(interfaceInfo);

        for (const layer of decodedPkt.layers) {
          expect(layer).toHaveProperty('protocolName');
          expect(layer).toHaveProperty('bytes');
          expect(layer.bytes).toBeInstanceOf(Buffer);
          // layer.bytes.length can be 0 for some protocols or layers without data
          // expect(layer.bytes.length).toBeGreaterThan(0);

          if (layer.protocolName !== 'Raw Data') {
            const decodedLayer = layer as DecodedPacketLayer;
            expect(decodedLayer).toHaveProperty('data');
            if (Object.prototype.hasOwnProperty.call(decodedLayer, 'payload')) {
              expect(decodedLayer.payload).toBeInstanceOf(Buffer);
            }
          }
        }
        // Add more specific assertions if the structure of couchbase-create-bucket.pcapng is known
        // For example, checking layer names if it's Ethernet -> IP -> TCP -> (Raw Data or Couchbase specific)
        if (decodedPkt.layers.length > 0) {
          const ethLayerObject = decodedPkt.layers[0];
          expect(ethLayerObject.protocolName).toBe('Ethernet II'); // Assuming Ethernet
          if (decodedPkt.layers.length > 1) {
            const ipLayerObject = decodedPkt.layers[1];
            expect(ipLayerObject.protocolName).toMatch(/^(IPv4|IPv6)$/);
            if (decodedPkt.layers.length > 2) {
              const tcpLayerObject = decodedPkt.layers[2];
              expect(tcpLayerObject.protocolName).toBe('TCP');
              if (tcpLayerObject.protocolName === 'TCP') {
                const tcpData = (tcpLayerObject as DecodedPacketLayer).data as TCPLayer;
                // Add assertions for tcpData if needed
                expect(tcpData).toBeDefined();
              }
            }
          }
        }
      }
    });

    it('should decode packets from couchbase-xattr.pcapng correctly', async () => {
      const filePath = path.join(dataDir, 'couchbase-xattr.pcapng');
      const fileBuffer = fs.readFileSync(filePath);

      for await (const packetData of iteratePcapNgPackets(fileBuffer)) {
        const timestamp = Number(packetData.timestamp) / 1_000_000_000.0;
        const interfaceInfo = {
          interfaceId: packetData.interface_id,
          name: packetData.interface_name,
          description: packetData.interface_description,
          linkType: packetData.interface_link_type,
        };

        const decodedPacket: DecodedPacket = decodePacket(
          packetData.packetData,
          packetData.interface_link_type,
          decoderRegistry,
          timestamp,
          packetData.originalLength,
          packetData.capturedLength,
          interfaceInfo,
        );

        expect(decodedPacket).toBeDefined();
        expect(decodedPacket.timestamp).toBeCloseTo(timestamp, 9);
        expect(decodedPacket.originalLength).toBe(packetData.originalLength);
        expect(decodedPacket.capturedLength).toBe(packetData.capturedLength);
        expect(decodedPacket.layers).toBeInstanceOf(Array);
        expect(decodedPacket.layers.length).toBeGreaterThan(0);
        expect(decodedPacket.interfaceInfo).toEqual(interfaceInfo);

        for (const layer of decodedPacket.layers) {
          expect(layer).toHaveProperty('protocolName');
          expect(layer).toHaveProperty('bytes');
          expect(layer.bytes).toBeInstanceOf(Buffer);
          if (layer.protocolName !== 'Raw Data') {
            const decodedLayer = layer as DecodedPacketLayer;
            expect(decodedLayer).toHaveProperty('data');
            if (Object.prototype.hasOwnProperty.call(decodedLayer, 'payload')) {
              expect(decodedLayer.payload).toBeInstanceOf(Buffer);
            }
          }
        }

        if (decodedPacket.layers.length > 0) {
          const ethLayerObject = decodedPacket.layers[0];
          expect(ethLayerObject.protocolName).toBe('Ethernet II'); // Assuming Ethernet
          if (decodedPacket.layers.length > 1) {
            const ipLayerObject = decodedPacket.layers[1];
            expect(ipLayerObject.protocolName).toMatch(/^(IPv4|IPv6)$/); // Couchbase likely uses IP
            if (decodedPacket.layers.length > 2) {
              const transportLayerObject = decodedPacket.layers[2];
              expect(transportLayerObject.protocolName).toBe('TCP'); // Couchbase typically uses TCP
              if (transportLayerObject.protocolName === 'TCP') {
                const tcpData = (transportLayerObject as DecodedPacketLayer).data as TCPLayer;
                // Add assertions for tcpData if needed
                expect(tcpData).toBeDefined();
              }
            }
          }
        }
      }
    });
    // Add more tests for other PCAPng files if needed
  });
  describe('Corrupted PCAP File Handling', () => {
    let consoleWarnSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
      // Spy on console.warn, as logWarning uses it.
      consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    });

    afterEach(() => {
      consoleWarnSpy.mockRestore();
    });

    it('should skip corrupted packets in corrupted_packets.pcap and log warnings', async () => {
      const filePath = path.join(dataDir, 'corrupted_packets.pcap');
      // This file needs to be created manually.
      // Structure: Global Header, Valid Packet 1, Corrupted Packet Record, Valid Packet 2
      if (!fs.existsSync(filePath)) {
        console.warn(`Test file ${filePath} not found. Skipping corrupted PCAP test.`);
        return;
      }
      const fileBuffer = fs.readFileSync(filePath);
      const globalHeader = parsePcapGlobalHeader(fileBuffer);
      if (!globalHeader)
        throw new Error('Could not parse PCAP global header for corrupted_packets.pcap');

      let packetCount = 0;
      for await (const packetData of iteratePcapPackets(fileBuffer)) {
        packetCount++;
        const timestamp = packetData.header.ts_sec + packetData.header.ts_usec / 1_000_000;
        const decodedPacket = decodePacket(
          packetData.packetData,
          globalHeader.network,
          decoderRegistry,
          timestamp,
          packetData.header.orig_len,
          packetData.header.incl_len,
        );
        expect(decodedPacket).toBeDefined();
        // Add more assertions if the content of valid packets is known
      }

      // Assuming corrupted_packets.pcap is structured to have 2 valid packets and 1 corrupted one.
      expect(packetCount).toBeGreaterThanOrEqual(1); // Should process at least the first valid packet
      expect(consoleWarnSpy).toHaveBeenCalled();
      // Example: expect(consoleWarnSpy).toHaveBeenCalledWith(expect.stringContaining('Skipping corrupted PCAP packet'));
    });
  });

  describe('Corrupted PCAPng File Handling', () => {
    let consoleWarnSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
      // Spy on console.warn, as logWarning uses it.
      consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    });

    afterEach(() => {
      consoleWarnSpy.mockRestore();
    });

    it('should skip corrupted blocks in corrupted_blocks.pcapng and log warnings', async () => {
      const filePath = path.join(dataDir, 'corrupted_blocks.pcapng');
      // This file needs to be created manually.
      // Structure: SHB, Valid EPB 1, Corrupted Block (e.g., bad length, bad type), Valid EPB 2
      if (!fs.existsSync(filePath)) {
        console.warn(`Test file ${filePath} not found. Skipping corrupted PCAPng test.`);
        return;
      }
      const fileBuffer = fs.readFileSync(filePath);

      let packetCount = 0;
      for await (const packetData of iteratePcapNgPackets(fileBuffer)) {
        packetCount++;
        const timestamp = Number(packetData.timestamp) / 1_000_000_000.0;
        const interfaceInfo = {
          interfaceId: packetData.interface_id,
          name: packetData.interface_name,
          description: packetData.interface_description,
          linkType: packetData.interface_link_type,
        };
        const decodedPacket = decodePacket(
          packetData.packetData,
          packetData.interface_link_type,
          decoderRegistry,
          timestamp,
          packetData.originalLength,
          packetData.capturedLength,
          interfaceInfo,
        );
        expect(decodedPacket).toBeDefined();
        // Add more assertions if the content of valid packets is known
      }
      // Assuming corrupted_blocks.pcapng is structured to have 2 valid packets and 1 corrupted block.
      expect(packetCount).toBeGreaterThanOrEqual(1); // Should process at least the first valid packet
      expect(consoleWarnSpy).toHaveBeenCalled();
      // Example: expect(consoleWarnSpy).toHaveBeenCalledWith(expect.stringContaining('Error parsing generic block header'));
      // Example: expect(consoleWarnSpy).toHaveBeenCalledWith(expect.stringContaining('Error parsing specific block type'));
    });
  });
});
