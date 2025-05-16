/**
 * Represents the flags in a DNS header.
 */
export interface DNSFlags {
  /** Query/Response flag: `0` for query, `1` for response. */
  QR: number;
  /** Operation code: `0` for standard query (QUERY), `1` for inverse query (IQUERY), `2` for server status request (STATUS). */
  Opcode: number;
  /** Authoritative Answer flag: `1` if the responding server is an authority for the domain name in question section. */
  AA: number;
  /** TrunCation flag: `1` if the message was truncated. */
  TC: number;
  /** Recursion Desired flag: `1` if recursion is desired. Set in queries. */
  RD: number;
  /** Recursion Available flag: `1` if recursive query support is available in the name server. Set in responses. */
  RA: number;
  /** Reserved for future use. Must be zero in all queries and responses. */
  Z: number;
  /** Response code: `0` for No error, `1` for Format error, `2` for Server failure, `3` for Name Error, etc. */
  RCODE: number;
}

/**
 * Represents a DNS question record.
 */
export interface DNSQuestion {
  /** The domain name being queried, as a string (e.g., "www.example.com"). */
  QNAME: string;
  /** The type of the query (e.g., 1 for A, 28 for AAAA, 15 for MX). See RFC 1035 and others for full list. */
  QTYPE: number;
  /** The class of the query (e.g., 1 for IN - Internet). */
  QCLASS: number;
}

/**
 * Represents a DNS resource record, used in Answer, Authority, and Additional sections.
 */
export interface DNSResourceRecord {
  /** The domain name to which this resource record pertains. */
  NAME: string;
  /** The type of the resource record (e.g., 1 for A, 5 for CNAME, 15 for MX). */
  TYPE: number;
  /** The class of the resource record (e.g., 1 for IN - Internet). */
  CLASS: number;
  /** The time interval (in seconds) that the resource record may be cached before it should be discarded. Zero means no caching. */
  TTL: number;
  /** The length (in octets) of the RDATA field. */
  RDLENGTH: number;
  /**
   * The resource data. The format varies based on the TYPE and CLASS of the resource record.
   * It can be a raw Buffer for unknown types, a string for types like CNAME or TXT,
   * or a more structured object for parsed types like A, AAAA, MX records (parsing to be implemented).
   */
  RDATA: Buffer | string | object;
}

/**
 * Represents the entire decoded DNS layer, including header, flags, and all sections.
 */
export interface DNSLayer {
  /** A 16-bit identifier assigned by the program that generates any kind of query. Also used in responses. */
  transactionId: number;
  /** The DNS flags. */
  flags: DNSFlags;
  /** The number of entries in the question section. */
  questionCount: number;
  /** The number of resource records in the answer section. */
  answerCount: number;
  /** The number of name server resource records in the authority records section. */
  authorityCount: number;
  /** The number of resource records in the additional records section. */
  additionalCount: number;
  /** An array of DNS questions. */
  questions: DNSQuestion[];
  /** An array of DNS resource records in the answer section. */
  answers: DNSResourceRecord[];
  /** An array of DNS resource records in the authority section. */
  authorities: DNSResourceRecord[];
  /** An array of DNS resource records in the additional section. */
  additionals: DNSResourceRecord[];
}
