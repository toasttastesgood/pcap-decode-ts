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
import type { DecodedPacketLayer } from '../../decode/packet-structures';

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

      for await (const packetData of iteratePcapPackets(fileBuffer)) {
        const timestamp = packetData.header.ts_sec + packetData.header.ts_usec / 1_000_000;
        const decodedPacket = decodePacket(
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
        if (decodedPacket.layers.length >= 3) {
          expect(decodedPacket.layers[0].protocolName).toBe('Ethernet II');
          expect(decodedPacket.layers[1].protocolName).toMatch(/^(IPv4|IPv6|ARP)$/); // Could be IPv4, IPv6 or ARP

          const ipLayer = decodedPacket.layers[1] as DecodedPacketLayer;
          if (ipLayer.protocolName === 'IPv4' || ipLayer.protocolName === 'IPv6') {
            expect(decodedPacket.layers[2].protocolName).toMatch(/^(TCP|UDP|ICMPv4|ICMPv6)$/);

            if (
              decodedPacket.layers.length >= 4 &&
              (decodedPacket.layers[2].protocolName === 'UDP' ||
                decodedPacket.layers[2].protocolName === 'TCP')
            ) {
              const transportLayer = decodedPacket.layers[2] as DecodedPacketLayer;
              // Check if DNS decoder produced a DNS layer or if it's raw data
              const appLayer = decodedPacket.layers[3];
              expect(appLayer.protocolName).toMatch(/^(DNS|HTTP|Raw Data)$/);

              // Check raw bytes and payload consistency
              const ethLayer = decodedPacket.layers[0] as DecodedPacketLayer;
              if (ethLayer.payload) {
                expect(
                  ipLayer.bytes.equals(ethLayer.payload.subarray(0, ipLayer.bytes.length)),
                ).toBe(true);
              }
              if (ipLayer.payload) {
                // Removed redundant check for 'Raw Data'
                const l3Payload = decodedPacket.layers[2] as DecodedPacketLayer;
                expect(
                  l3Payload.bytes.equals(ipLayer.payload.subarray(0, l3Payload.bytes.length)),
                ).toBe(true);
              }
              if (transportLayer.payload && decodedPacket.layers[3].protocolName !== 'Raw Data') {
                const l4Payload = decodedPacket.layers[3] as DecodedPacketLayer;
                expect(
                  l4Payload.bytes.equals(
                    transportLayer.payload.subarray(0, l4Payload.bytes.length),
                  ),
                ).toBe(true);
              }
            }
          }
        }
      }
    });

    // Add more tests for other PCAP files if needed
    // e.g., it('should decode packets from ipv4frags.pcap correctly', () => { ... });
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

        expect(decodedPacket).toBeDefined();
        expect(decodedPacket.timestamp).toBeCloseTo(timestamp, 9); // Compare with high precision
        expect(decodedPacket.originalLength).toBe(packetData.originalLength);
        expect(decodedPacket.capturedLength).toBe(packetData.capturedLength);
        expect(decodedPacket.layers).toBeInstanceOf(Array);
        expect(decodedPacket.layers.length).toBeGreaterThan(0);
        expect(decodedPacket.interfaceInfo).toEqual(interfaceInfo);

        for (const layer of decodedPacket.layers) {
          expect(layer).toHaveProperty('protocolName');
          expect(layer).toHaveProperty('bytes');
          expect(layer.bytes).toBeInstanceOf(Buffer);
          expect(layer.bytes.length).toBeGreaterThan(0);

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
        if (decodedPacket.layers.length > 0) {
          expect(decodedPacket.layers[0].protocolName).toBe('Ethernet II'); // Assuming Ethernet
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
