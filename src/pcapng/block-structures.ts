// src/pcapng/block-structures.ts

/**
 * Represents a generic PCAPng Option with code, length, and raw value.
 * Options are used to add optional information to blocks.
 */
export interface PcapNgOption {
  code: number;
  length: number;
  value: Buffer; // Raw option value, specific parsing depends on the option code and block type
}

/**
 * Generic Block Header structure for all PCAPng blocks.
 * All blocks start with these two fields, followed by the block body and
 * then a repetition of the block_total_length.
 */
export interface PcapNgGenericBlockHeader {
  block_type: number;
  block_total_length: number;
}

/**
 * Section Header Block (SHB)
 * Block Type ID: 0x0A0D0D0A
 * The SHB is the first block of a PCAPng file (or a section within it)
 * and defines characteristics for that section.
 */
export interface PcapNgSectionHeaderBlock extends PcapNgGenericBlockHeader {
  byte_order_magic: number; // Magic number (0x1A2B3C4D) to detect endianness.
  major_version: number; // Major version of the PCAPng format (current is 1).
  minor_version: number; // Minor version of the PCAPng format (current is 0).
  section_length: bigint; // Length of this section in bytes. A value of -1 (0xFFFFFFFFFFFFFFFF)
  // means that the length is unspecified.
  options: PcapNgOption[]; // Optional fields.
}

/**
 * Interface Description Block (IDB)
 * Block Type ID: 0x00000001
 * Describes an interface on which packet data was captured.
 * An IDB is typically present for each interface.
 */
export interface PcapNgInterfaceDescriptionBlock extends PcapNgGenericBlockHeader {
  linktype: number; // Data link type (e.g., LINKTYPE_ETHERNET).
  reserved: number; // Reserved, must be 0. (2 bytes)
  snaplen: number; // Maximum number of bytes dumped from each packet.
  // A value of 0 means no limit.
  options: PcapNgOption[]; // Optional fields (e.g., if_name, if_tsresol).
}

/**
 * Enhanced Packet Block (EPB)
 * Block Type ID: 0x00000006
 * Contains a single captured packet, or a portion of it.
 * This is the preferred block for storing packet data.
 */
export interface PcapNgEnhancedPacketBlock extends PcapNgGenericBlockHeader {
  interface_id: number; // Interface ID indicating the interface this packet was captured on.
  timestamp_high: number; // Upper 32 bits of a 64-bit timestamp.
  timestamp_low: number; // Lower 32 bits of a 64-bit timestamp.
  captured_len: number; // Number of bytes captured from the packet and stored in this block.
  original_len: number; // Actual length of the packet when it was transmitted on the network.
  packet_data: Buffer; // The captured packet data.
  options: PcapNgOption[]; // Optional fields.
}

/**
 * Simple Packet Block (SPB)
 * Block Type ID: 0x00000003
 * Contains a single captured packet, with minimal information.
 * This block is considered obsolete; EPB should be used instead.
 */
export interface PcapNgSimplePacketBlock extends PcapNgGenericBlockHeader {
  original_len: number; // Actual length of the packet when it was transmitted on the network.
  packet_data: Buffer; // The captured packet data (captured_len is block_total_length - 16).
  // Note: Simple Packet Block does not have an options field.
}

/**
 * Represents a single name resolution record within a Name Resolution Block (NRB).
 * These records map addresses (like IP addresses) to names (like hostnames).
 */
export interface PcapNgNameResolutionRecord {
  record_type: number; // Type of record (e.g., 1 for IPv4, 2 for IPv6).
  record_value_length: number; // Length of the record_value field.
  record_value: Buffer; // Contains the address and associated names.
  // Format depends on record_type. Typically an address
  // followed by one or more null-terminated UTF-8 strings.
}

/**
 * Name Resolution Block (NRB)
 * Block Type ID: 0x00000004
 * Contains records that map numerical addresses to human-readable names.
 */
export interface PcapNgNameResolutionBlock extends PcapNgGenericBlockHeader {
  records: PcapNgNameResolutionRecord[]; // List of name resolution records.
  options: PcapNgOption[]; // Optional fields (e.g., ns_dnsname).
}

/**
 * Interface Statistics Block (ISB)
 * Block Type ID: 0x00000005
 * Provides statistics for a specific capture interface.
 */
export interface PcapNgInterfaceStatisticsBlock extends PcapNgGenericBlockHeader {
  interface_id: number; // Interface ID for which these statistics apply.
  timestamp_high: number; // Upper 32 bits of a 64-bit timestamp indicating when stats were collected.
  timestamp_low: number; // Lower 32 bits of the timestamp.
  options: PcapNgOption[]; // Optional fields containing actual statistics
  // (e.g., isb_ifrecv, isb_ifdrop).
}

/**
 * PCAPng Block Type Codes
 * These are the unique identifiers for each block type, used in PcapNgGenericBlockHeader.block_type.
 */
export enum PcapNgBlockType {
  SectionHeader = 0x0a0d0d0a,
  InterfaceDescription = 0x00000001,
  ObsoletePacket = 0x00000002, // Not implementing as per common practice, obsolete
  SimplePacket = 0x00000003,
  NameResolution = 0x00000004,
  InterfaceStatistics = 0x00000005,
  EnhancedPacket = 0x00000006,
  // The following are other defined block types, not explicitly requested for this task
  // IRIGTimestamp = 0x00000007,
  // Arinc429 = 0x00000008,
  // Packet = 0x00000009, // Alternative to EPB/SPB, less common
  // SystemdJournalExport = 0x0000000A,
  // DecryptionSecrets = 0x0000000B,
  CustomCanBeCopied = 0x00000bad, // Custom Block that tools can copy if not understood
  CustomDoNotCopy = 0x40000bad, // Custom Block that tools should not copy if not understood
}
