import { describe, bench, beforeAll } from 'vitest';
import { readFile } from 'fs/promises';
import { Buffer } from 'buffer';
import { iteratePcapPackets } from '../src/pcap/pcap-iterator';
import { iteratePcapNgPackets } from '../src/pcapng/pcapng-iterator';
import { decodePacket } from '../src/decode/packet-decoder';
import { DecoderRegistry } from '../src/decode/decoder-registry';
import { Ethernet2Decoder } from '../src/decode/ethernet/ethernet2-decoder';
import { IPv4Decoder } from '../src/decode/ipv4/ipv4-decoder';
import { IPv6Decoder } from '../src/decode/ipv6/ipv6-decoder';
import { TCPDecoder } from '../src/decode/tcp/tcp-decoder';
import { UDPDecoder } from '../src/decode/udp/udp-decoder';
import { ICMPv4Decoder } from '../src/decode/icmpv4/icmpv4-decoder';
import { ICMPv6Decoder } from '../src/decode/icmpv6/icmpv6-decoder';
import { ARPDecoder } from '../src/decode/arp/arp-decoder';
import { DNSDecoder } from '../src/decode/dns/dns-decoder';
import { HTTP1Decoder } from '../src/decode/http/http1-decoder';
import { PcapPacket } from '../src/pcap/pcap-iterator';
import { PcapNgPacket } from '../src/pcapng/pcapng-iterator';

// Paths to sample files (assuming they exist or will be created)
const LARGE_PCAP_FILE = 'src/test/data/large_sample.pcap'; // Placeholder - ensure this file exists
const LARGE_PCAPNG_FILE = 'src/test/data/large_sample.pcapng'; // Placeholder - ensure this file exists
const DIVERSE_PACKETS_PCAP_FILE = 'src/test/data/diverse_packets.pcap'; // Placeholder - ensure this file exists

// Common Protocol Identifiers
const LINKTYPE_ETHERNET = 1;
const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_ARP = 0x0806;
const ETHERTYPE_IPV6 = 0x86dd;
const IPPROTOCOL_ICMP = 1;
const IPPROTOCOL_TCP = 6;
const IPPROTOCOL_UDP = 17;
const IPPROTOCOL_ICMPV6 = 58;
const PORT_DNS = 53;
const PORT_HTTP = 80;
// Add other ports if your HTTP decoder handles them, e.g., 8080

describe('PCAP File Parsing Performance', () => {
  let pcapBuffer: Buffer;

  beforeAll(async () => {
    try {
      pcapBuffer = await readFile(LARGE_PCAP_FILE);
    } catch (error) {
      console.warn(
        `Warning: Could not read ${LARGE_PCAP_FILE} for benchmarking. PCAP parsing benchmarks will be skipped. Error: ${(error as Error).message}`,
      );
      // pcapBuffer will remain undefined, and tests should handle this
    }
  });

  bench(
    'Iterate and parse all packets from a large PCAP file',
    async () => {
      if (!pcapBuffer) {
        console.warn(`Skipping PCAP iteration benchmark as ${LARGE_PCAP_FILE} was not loaded.`);
        return;
      }
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      for await (const _packet of iteratePcapPackets(pcapBuffer)) {
        // Intentionally empty loop body, we are measuring iteration and parsing
      }
    },
    { iterations: 10, time: 10000 },
  ); // Adjust iterations/time as needed
});

describe('PCAPng File Parsing Performance', () => {
  let pcapNgBuffer: Buffer;

  beforeAll(async () => {
    try {
      pcapNgBuffer = await readFile(LARGE_PCAPNG_FILE);
    } catch (error) {
      console.warn(
        `Warning: Could not read ${LARGE_PCAPNG_FILE} for benchmarking. PCAPng parsing benchmarks will be skipped. Error: ${(error as Error).message}`,
      );
    }
  });

  bench(
    'Iterate and parse all packets from a large PCAPng file',
    async () => {
      if (!pcapNgBuffer) {
        console.warn(`Skipping PCAPng iteration benchmark as ${LARGE_PCAPNG_FILE} was not loaded.`);
        return;
      }
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      for await (const _packet of iteratePcapNgPackets(pcapNgBuffer)) {
        // Intentionally empty loop body
      }
    },
    { iterations: 10, time: 10000 },
  );
});

describe('Packet Decoding Pipeline Performance', () => {
  const packetsForDecoding: (PcapPacket | PcapNgPacket)[] = [];
  let decoderRegistry: DecoderRegistry;

  beforeAll(async () => {
    decoderRegistry = new DecoderRegistry();
    // Register link layer decoders
    decoderRegistry.registerDecoder(LINKTYPE_ETHERNET, new Ethernet2Decoder());

    // Register network layer decoders (identified by EtherType from Ethernet layer)
    decoderRegistry.registerDecoder(ETHERTYPE_ARP, new ARPDecoder());
    decoderRegistry.registerDecoder(ETHERTYPE_IPV4, new IPv4Decoder());
    decoderRegistry.registerDecoder(ETHERTYPE_IPV6, new IPv6Decoder());

    // Register transport layer decoders (identified by Protocol number from IP layer)
    decoderRegistry.registerDecoder(IPPROTOCOL_TCP, new TCPDecoder());
    decoderRegistry.registerDecoder(IPPROTOCOL_UDP, new UDPDecoder());
    decoderRegistry.registerDecoder(IPPROTOCOL_ICMP, new ICMPv4Decoder());
    decoderRegistry.registerDecoder(IPPROTOCOL_ICMPV6, new ICMPv6Decoder());

    // Register application layer decoders (identified by port number from TCP/UDP layer)
    // The TCP/UDP decoders' nextProtocolType method should return these port numbers.
    decoderRegistry.registerDecoder(PORT_DNS, new DNSDecoder());
    decoderRegistry.registerDecoder(PORT_HTTP, new HTTP1Decoder());
    // If HTTP1Decoder handles other ports, register them too:
    // decoderRegistry.registerDecoder(8080, new HTTP1Decoder());

    try {
      const diversePacketsBuffer = await readFile(DIVERSE_PACKETS_PCAP_FILE);
      // For simplicity, using PCAP iterator here. Could adapt for PCAPng if needed.
      for await (const packet of iteratePcapPackets(diversePacketsBuffer)) {
        packetsForDecoding.push(packet);
        if (packetsForDecoding.length >= 100) break; // Limit number of packets for benchmark
      }
      if (packetsForDecoding.length === 0) {
        console.warn(
          `Warning: No packets loaded from ${DIVERSE_PACKETS_PCAP_FILE}. Decoding benchmark might not run effectively.`,
        );
      }
    } catch (error) {
      console.warn(
        `Warning: Could not read ${DIVERSE_PACKETS_PCAP_FILE} for benchmarking. Decoding benchmark will be skipped or run with no packets. Error: ${(error as Error).message}`,
      );
    }
  });

  bench(
    'Decode a set of diverse packets',
    () => {
      if (packetsForDecoding.length === 0) {
        console.warn(
          `Skipping decoding benchmark as no packets were loaded from ${DIVERSE_PACKETS_PCAP_FILE}.`,
        );
        return;
      }
      for (const pcapPacket of packetsForDecoding) {
        // Assuming PcapPacket structure for linkType, adapt if PcapNgPacket has different structure for this
        // For PCAP, global header linktype is needed. For PCAPng, IDB linktype.
        // This benchmark setup is simplified and assumes a common link type or that decoder handles it.
        // For a robust benchmark, one might need to fetch link_type from the PcapPacket's global header context
        // or PcapNgPacket's interface description.
        // For now, let's assume Ethernet (1) as a common case for test data.
        // The link layer type for PCAP files is typically found in the global header,
        // and for PCAPng in the Interface Description Block.
        // For this benchmark, we'll use LINKTYPE_ETHERNET (1) assuming test data consistency.
        // The actual link type would come from the PCAP global header or PCAPng IDB.
        decodePacket(pcapPacket.packetData, LINKTYPE_ETHERNET, decoderRegistry);
      }
    },
    { iterations: 100, time: 10000 },
  ); // Adjust iterations/time
});
