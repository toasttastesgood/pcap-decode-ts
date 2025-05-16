/**
 * @module pcap-decoder-ts
 *
 * This module exports the core functionalities of the pcap-decoder-ts library,
 * allowing users to parse and decode network packet captures in PCAP and PCAPng formats.
 */

export * from './errors';

// PCAP specific exports
export * from './pcap/pcap-iterator';
export * from './pcap/global-header';
export * from './pcap/packet-record-header';
export * from './pcap/global-header-parser';
export * from './pcap/packet-record-parser';

// PCAPng specific exports
export * from './pcapng/pcapng-iterator';
export * from './pcapng/block-structures';
export * from './pcapng/block-parsers';
export * from './pcapng/generic-block-parser';

// Decoding engine exports
export * from './decode/decoder';
export * from './decode/decoder-registry';
export * from './decode/packet-decoder';
export * from './decode/packet-structures';

// Specific Layer Decoders (optional, can be extensive)
// Users can also access these via the DecoderRegistry
export * from './decode/arp/arp-decoder';
export * from './decode/dns/dns-decoder';
export * from './decode/dns/dns-layer';
export * from './decode/ethernet/ethernet2-decoder';
export * from './decode/http/http1-decoder';
export * from './decode/http/http1-layer';
export * from './decode/icmpv4/icmpv4-decoder';
export * from './decode/icmpv4/icmpv4-layer';
export * from './decode/icmpv6/icmpv6-decoder';
// export * from './decode/icmpv6/icmpv6-layer'; // No separate layer file, ICMPv6Layer is in icmpv6-decoder.ts
export * from './decode/ipv4/ipv4-decoder';
export * from './decode/ipv4/ipv4-layer';
export * from './decode/ipv6/ipv6-decoder';
export * from './decode/ipv6/ipv6-layer';
export * from './decode/tcp/tcp-decoder';
export * from './decode/tcp/tcp-layer';
export * from './decode/udp/udp-decoder';

// Utility exports (if any are intended for public API)
export * from './utils/byte-readers'; // Assuming ByteReader is a core utility
export * from './utils/ip-formatters';
export * from './utils/mac-address-formatter';
export * from './utils/logger'; // If configurable logger is part of public API
export * from './utils/service-names';

/**
 * @typedef {import('./decode/packet-structures').DecodedPacket} DecodedPacket
 * @typedef {import('./decode/packet-structures').PacketLayer} PacketLayer
 * @typedef {import('./pcap/pcap-iterator').PcapPacket} PcapPacket
 * @typedef {import('./pcapng/pcapng-iterator').PcapNgPacket} PcapNgPacket
 */
