import { Decoder, DecoderOutputLayer } from '../decoder';
import { DNSLayer, DNSFlags, DNSQuestion, DNSResourceRecord } from './dns-layer';
import { BufferOutOfBoundsError, PcapDecodingError } from '../../errors'; // Added PcapDecodingError
import { readUint16BE, readUint8, readUint32BE } from '../../utils/byte-readers'; // Added readUint32BE
import { formatIPv4, formatIPv6 } from '../../utils/ip-formatters';

// DNS Record Types (RFC 1035 and others)
const RR_TYPE_A = 1;
const RR_TYPE_NS = 2;
const RR_TYPE_CNAME = 5;
const RR_TYPE_SOA = 6;
const RR_TYPE_PTR = 12;
const RR_TYPE_MX = 15;
const RR_TYPE_TXT = 16;
const RR_TYPE_AAAA = 28;

// DNS Class
const RR_CLASS_IN = 1;

const DNS_HEADER_LENGTH = 12;
const MAX_NAME_POINTER_RECURSION = 10; // To prevent infinite loops with bad compression pointers
const MAX_LABEL_LENGTH = 63;
const MAX_NAME_OCTETS = 255;

/**
 * Decodes DNS (Domain Name System) protocol messages.
 * This decoder parses the DNS header, questions, and resource records (answers, authorities, additionals).
 * It supports DNS name compression.
 */
export class DNSDecoder implements Decoder<DNSLayer> {
  /**
   * The human-readable name for this protocol.
   */
  public readonly protocolName = 'DNS';

  /**
   * Decodes a DNS message from the provided buffer.
   *
   * @param buffer - The buffer containing the DNS message, starting at the DNS header.
   * @param offset - The offset within the buffer where the DNS message begins. Defaults to `0`.
   * @returns A {@link DecoderOutputLayer} object containing the parsed {@link DNSLayer} data.
   * @throws {BufferOutOfBoundsError} If the buffer is too small for the DNS header or declared record lengths.
   * @throws {PcapDecodingError} If malformed data is encountered (e.g., invalid name compression, invalid label type).
   */
  public decode(buffer: Buffer, offset = 0): DecoderOutputLayer<DNSLayer> {
    if (buffer.length - offset < DNS_HEADER_LENGTH) {
      // Corrected error instantiation
      throw new BufferOutOfBoundsError(
        `Buffer too small for DNS header at offset ${offset}. Expected ${DNS_HEADER_LENGTH} bytes, got ${buffer.length - offset}.`,
      );
    }

    const transactionId = readUint16BE(buffer, offset); // Corrected function name
    const flagsRaw = readUint16BE(buffer, offset + 2); // Corrected function name
    const questionCount = readUint16BE(buffer, offset + 4); // Corrected function name
    const answerCount = readUint16BE(buffer, offset + 6); // Corrected function name
    const authorityCount = readUint16BE(buffer, offset + 8); // Corrected function name
    const additionalCount = readUint16BE(buffer, offset + 10); // Corrected function name

    const flags: DNSFlags = {
      QR: (flagsRaw >> 15) & 0x1,
      Opcode: (flagsRaw >> 11) & 0xf,
      AA: (flagsRaw >> 10) & 0x1,
      TC: (flagsRaw >> 9) & 0x1,
      RD: (flagsRaw >> 8) & 0x1,
      RA: (flagsRaw >> 7) & 0x1,
      Z: (flagsRaw >> 4) & 0x7, // Reserved bits
      RCODE: flagsRaw & 0xf,
    };

    // Placeholder for parsing questions, answers, authorities, additionals
    const questions: DNSQuestion[] = [];
    const answers: DNSResourceRecord[] = [];
    const authorities: DNSResourceRecord[] = [];
    const additionals: DNSResourceRecord[] = [];

    let currentOffset = offset + DNS_HEADER_LENGTH;

    // Parse Questions
    for (let i = 0; i < questionCount; i++) {
      if (currentOffset >= buffer.length) {
        throw new BufferOutOfBoundsError(
          `Buffer too small for DNS Question ${i + 1} at offset ${currentOffset}. Needed at least 1 byte for QNAME length, got ${buffer.length - currentOffset}.`,
        );
      }
      const qNameResult = this._parseQName(buffer, currentOffset, offset);
      questions.push({
        QNAME: qNameResult.name,
        QTYPE: readUint16BE(buffer, currentOffset + qNameResult.bytesRead),
        QCLASS: readUint16BE(buffer, currentOffset + qNameResult.bytesRead + 2),
      });
      currentOffset += qNameResult.bytesRead + 4; // QNAME + QTYPE (2) + QCLASS (2)
    }

    // Parse Answers
    for (let i = 0; i < answerCount; i++) {
      if (currentOffset >= buffer.length) {
        throw new BufferOutOfBoundsError(
          `Buffer too small for DNS Answer RR ${i + 1} at offset ${currentOffset}. Needed at least 1 byte for NAME length, got ${buffer.length - currentOffset}.`,
        );
      }
      const rrResult = this._parseResourceRecord(buffer, currentOffset, offset);
      answers.push(rrResult.record);
      currentOffset += rrResult.bytesRead;
    }

    // Parse Authorities
    for (let i = 0; i < authorityCount; i++) {
      if (currentOffset >= buffer.length) {
        throw new BufferOutOfBoundsError(
          `Buffer too small for DNS Authority RR ${i + 1} at offset ${currentOffset}. Needed at least 1 byte for NAME length, got ${buffer.length - currentOffset}.`,
        );
      }
      const rrResult = this._parseResourceRecord(buffer, currentOffset, offset);
      authorities.push(rrResult.record);
      currentOffset += rrResult.bytesRead;
    }

    // Parse Additionals
    for (let i = 0; i < additionalCount; i++) {
      if (currentOffset >= buffer.length) {
        throw new BufferOutOfBoundsError(
          `Buffer too small for DNS Additional RR ${i + 1} at offset ${currentOffset}. Needed at least 1 byte for NAME length, got ${buffer.length - currentOffset}.`,
        );
      }
      const rrResult = this._parseResourceRecord(buffer, currentOffset, offset);
      additionals.push(rrResult.record);
      currentOffset += rrResult.bytesRead;
    }

    const dnsLayer: DNSLayer = {
      transactionId,
      flags,
      questionCount,
      answerCount,
      authorityCount,
      additionalCount,
      questions,
      answers,
      authorities,
      additionals,
    };

    // The actual number of bytes consumed by the DNS message.
    const totalBytesConsumed = currentOffset - offset;
    const payload = buffer.subarray(currentOffset);

    return {
      protocolName: this.protocolName,
      headerLength: totalBytesConsumed, // This is the total length of the DNS message processed
      data: dnsLayer,
      payload: payload,
    };
  }

  /**
   * Determines the next protocol type. For DNS, this is typically null as it's an
   * application layer protocol and doesn't encapsulate another protocol in the same way
   * transport or network layers do.
   *
   * @param _decodedLayer - The current decoded DNS layer data. Not used by this method.
   * @returns `null`, as DNS is usually a terminal protocol in the decoding chain.
   */
  public nextProtocolType(_decodedLayer: DNSLayer): string | null {
    return null; // DNS is typically an application layer protocol
  }

  /**
   * Parses a DNS domain name (QNAME or NAME field).
   * Handles normal labels and compression pointers.
   * @param buffer The buffer containing the DNS message.
   * @param nameOffset The offset within the buffer where the name starts.
   * @param messageStartOffset The offset of the beginning of the DNS message, for pointer calculations.
   * @returns The parsed name and the number of bytes read for this name (excluding jumps for pointers).
   */
  private _parseQName(
    buffer: Buffer,
    nameOffset: number,
    messageStartOffset: number,
    recursionDepth = 0,
  ): { name: string; bytesRead: number } {
    if (recursionDepth > MAX_NAME_POINTER_RECURSION) {
      throw new PcapDecodingError(
        `DNS name compression loop detected at offset ${nameOffset}. Exceeded max recursion depth of ${MAX_NAME_POINTER_RECURSION}.`,
      );
    }

    const labels: string[] = [];
    let currentReadOffset = nameOffset;
    let bytesConsumedForThisName = 0; // Tracks bytes consumed by this specific name part, not by following pointers.
    let followedPointer = false;

    while (currentReadOffset < buffer.length) {
      const lengthByte = readUint8(buffer, currentReadOffset);
      if (lengthByte === 0) {
        // End of name
        currentReadOffset++;
        if (!followedPointer) bytesConsumedForThisName++;
        break;
      }

      if ((lengthByte & 0xc0) === 0xc0) {
        // Compression pointer
        if (currentReadOffset + 1 >= buffer.length) {
          throw new BufferOutOfBoundsError(
            `Incomplete DNS name compression pointer at offset ${currentReadOffset}. Need 2 bytes, got ${buffer.length - currentReadOffset}.`,
          );
        }
        const pointer = readUint16BE(buffer, currentReadOffset) & 0x3fff;
        if (messageStartOffset + pointer >= buffer.length) {
          throw new BufferOutOfBoundsError(
            `DNS name compression pointer 0x${pointer.toString(16)} (offset ${messageStartOffset + pointer}) at offset ${currentReadOffset} is out of bounds (buffer length ${buffer.length}).`,
          );
        }

        const pointedNameResult = this._parseQName(
          buffer,
          messageStartOffset + pointer,
          messageStartOffset,
          recursionDepth + 1,
        );
        // If the pointed name is empty (root), labels.push("") is fine. join will handle it.
        labels.push(pointedNameResult.name);
        currentReadOffset += 2; // Pointer is 2 bytes
        if (!followedPointer) bytesConsumedForThisName += 2;
        followedPointer = true; // After a pointer, subsequent bytes are not part of this name's length
        break; // Name is resolved by the pointer
      } else if ((lengthByte & 0xc0) === 0x00) {
        // Normal label
        const labelLength = lengthByte;
        if (labelLength > MAX_LABEL_LENGTH) {
          throw new PcapDecodingError(
            `DNS label at offset ${currentReadOffset} too long: ${labelLength} bytes (max ${MAX_LABEL_LENGTH}).`,
          );
        }
        currentReadOffset++; // Consume length byte
        if (currentReadOffset + labelLength > buffer.length) {
          throw new BufferOutOfBoundsError(
            `DNS label length ${labelLength} at offset ${currentReadOffset - 1} exceeds buffer bounds (buffer length ${buffer.length}).`,
          );
        }
        labels.push(buffer.toString('ascii', currentReadOffset, currentReadOffset + labelLength));
        currentReadOffset += labelLength;
        if (!followedPointer) bytesConsumedForThisName += 1 + labelLength;
      } else {
        // Invalid label type (e.g., 0x80 or 0x40 start bits are reserved/unused)
        throw new PcapDecodingError(
          `Invalid DNS label type: 0x${lengthByte.toString(16)} at offset ${currentReadOffset}. First two bits must be 00 or 11.`,
        );
      }
    }

    // Check for unterminated name if we ran out of buffer before a null byte or valid pointer
    // This check is implicitly handled by loop condition and BufferOutOfBoundsError inside,
    // but an explicit check if no labels were parsed and loop ended might be useful.
    if (labels.length === 0 && currentReadOffset === nameOffset && currentReadOffset >= buffer.length) {
        // This means the buffer ended right where the name was supposed to start, or was empty.
        // The loop `currentReadOffset < buffer.length` wouldn't even run.
        // The checks at the beginning of decode() or section parsing should catch this.
        // If it did run, lengthByte would be read. If buffer ends, readUint8 might throw.
    }


    const finalNameString = labels.join('.');
    let conceptualTotalWireLength = 0;

    if (finalNameString === "") { // Root label "." is represented as an empty string by `_parseQName` when it's just a 0x00 byte.
        conceptualTotalWireLength = 1; // Represents the single null terminator byte for the root.
    } else {
        const nameSegments = finalNameString.split('.');
        conceptualTotalWireLength = 1; // For the final null terminator byte.
        for (const segment of nameSegments) {
            // Each segment has a length byte + its characters.
            // An empty segment (e.g., from "foo..bar" if _parseQName produced it) would have segment.length 0, contributing 1 byte (length octet 0).
            // Standard names like "www.example.com" will have non-empty segments.
            conceptualTotalWireLength += (1 + segment.length);
        }
    }

    if (conceptualTotalWireLength > MAX_NAME_OCTETS) {
      throw new PcapDecodingError(
        `Resolved DNS name "${finalNameString}" starting at offset ${nameOffset} exceeds ${MAX_NAME_OCTETS} octet limit (conceptual on-wire length: ${conceptualTotalWireLength}).`,
      );
    }

    // Note: Unterminated names (running out of buffer before a null byte or valid pointer)
    // are primarily caught by BufferOutOfBoundsErrors within the label/pointer parsing logic inside the loop.
    return { name: finalNameString, bytesRead: bytesConsumedForThisName };
  }

  /**
   * Parses a DNS Resource Record (Answer, Authority, or Additional).
   * @param buffer The buffer containing the DNS message.
   * @param rrOffset The offset within the buffer where the RR starts.
   * @param messageStartOffset The offset of the beginning of the DNS message, for pointer calculations in NAME.
   * @returns The parsed RR and the number of bytes read for this RR.
   */
  private _parseResourceRecord(
    buffer: Buffer,
    rrOffset: number,
    messageStartOffset: number,
  ): { record: DNSResourceRecord; bytesRead: number } {
    let currentReadOffset = rrOffset;

    const nameResult = this._parseQName(buffer, currentReadOffset, messageStartOffset);
    currentReadOffset += nameResult.bytesRead;

    const RR_FIXED_HEADER_SIZE = 10; // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
    if (currentReadOffset + RR_FIXED_HEADER_SIZE > buffer.length) {
      throw new BufferOutOfBoundsError(
        `Buffer too small for DNS RR fixed header fields (TYPE, CLASS, TTL, RDLENGTH) for NAME ${nameResult.name} at offset ${currentReadOffset}. Expected ${RR_FIXED_HEADER_SIZE} bytes, got ${buffer.length - currentReadOffset}.`,
      );
    }

    const type = readUint16BE(buffer, currentReadOffset);
    currentReadOffset += 2;
    const rrClass = readUint16BE(buffer, currentReadOffset);
    currentReadOffset += 2;
    const ttl = readUint32BE(buffer, currentReadOffset);
    currentReadOffset += 4;
    const rdLength = readUint16BE(buffer, currentReadOffset);
    currentReadOffset += 2;

    if (currentReadOffset + rdLength > buffer.length) {
      throw new BufferOutOfBoundsError(
        `Buffer too small for DNS RR RDATA for NAME ${nameResult.name} (TYPE: ${type}, CLASS: ${rrClass}) at offset ${currentReadOffset}. Expected RDLENGTH ${rdLength} bytes, got ${buffer.length - currentReadOffset}.`,
      );
    }

    const rdata = buffer.subarray(currentReadOffset, currentReadOffset + rdLength);
    currentReadOffset += rdLength;

    const parsedRData = this._parseRData(
      type,
      rrClass,
      rdata,
      buffer, // Full message buffer
      messageStartOffset, // Start of the DNS message in the full buffer
      currentReadOffset - rdLength, // Start of RDATA in the full message buffer
    );

    const record: DNSResourceRecord = {
      NAME: nameResult.name,
      TYPE: type,
      CLASS: rrClass,
      TTL: ttl,
      RDLENGTH: rdLength,
      RDATA: parsedRData,
    };

    return { record, bytesRead: currentReadOffset - rrOffset };
  }

  /**
   * Parses the RDATA field of a DNS Resource Record based on its type and class.
   * @param type The RR type.
   * @param rrClass The RR class.
   * @param rdataBuffer The buffer containing only the RDATA.
   * @param fullMessageBuffer The buffer for the entire DNS message (for name compression).
   * @param messageStartOffset The offset of the DNS message start within fullMessageBuffer.
   * @param rdataStartInFullMsgOffset The absolute offset where rdataBuffer begins within fullMessageBuffer.
   * @returns Parsed RDATA (string, object) or the raw rdataBuffer if not parsed.
   */
  private _parseRData(
    type: number,
    rrClass: number,
    rdataBuffer: Buffer,
    fullMessageBuffer: Buffer,
    messageStartOffset: number,
    rdataStartInFullMsgOffset: number,
  ): Buffer | string | object {
    if (rrClass !== RR_CLASS_IN) {
      return rdataBuffer; // Only parsing IN class for now
    }

    try {
      switch (type) {
        case RR_TYPE_A:
          if (rdataBuffer.length === 4) {
            return formatIPv4(rdataBuffer);
          }
          break;
        case RR_TYPE_AAAA:
          if (rdataBuffer.length === 16) {
            return formatIPv6(rdataBuffer);
          }
          break;
        case RR_TYPE_CNAME:
        case RR_TYPE_NS:
        case RR_TYPE_PTR:
          // These types contain a domain name.
          // The name is parsed from the rdataStartInFullMsgOffset within fullMessageBuffer.
          // The _parseQName's `bytesRead` will be relative to the start of the name within RDATA.
          // We need to ensure _parseQName doesn't read past rdataBuffer.length if no compression.
          const nameResult = this._parseQName(
            fullMessageBuffer,
            rdataStartInFullMsgOffset, // Name parsing starts at the beginning of RDATA
            messageStartOffset,
          );
          // Check if the bytes representing the name itself (if uncompressed or partially compressed in RDATA)
          // exceed the bounds of the RDATA.
          if (nameResult.bytesRead > rdataBuffer.length) {
            throw new PcapDecodingError(
              `RDATA name (type ${type}) representation (length ${nameResult.bytesRead}) starting at offset ${rdataStartInFullMsgOffset} exceeds RDLENGTH (${rdataBuffer.length}).`,
            );
          }
          return nameResult.name;
        // REMOVED ERRONEOUS '}' HERE
        case RR_TYPE_MX:
          if (rdataBuffer.length < 2) { // Not enough for preference
            break; // Fallback to raw RDATA
          }
          const preference = readUint16BE(rdataBuffer, 0);
          const exchangeNameOffsetInRData = 2;

          // MX record requires an exchange name. At least 1 byte for null terminator of root domain.
          if (rdataBuffer.length <= exchangeNameOffsetInRData) {
            throw new PcapDecodingError(
              `MX RDATA (length ${rdataBuffer.length}) at offset ${rdataStartInFullMsgOffset} is too short for an exchange name after preference (requires > 2 bytes).`
            );
          }

          const exchangeNameResult = this._parseQName(
            fullMessageBuffer,
            rdataStartInFullMsgOffset + exchangeNameOffsetInRData,
            messageStartOffset,
          );
          // Check if the bytes representing the exchange name itself
          // exceed the bounds of the RDATA allocated for the name part.
          if (exchangeNameResult.bytesRead > rdataBuffer.length - exchangeNameOffsetInRData) {
            throw new PcapDecodingError(
              `MX RDATA exchange name representation (length ${exchangeNameResult.bytesRead}) starting at offset ${rdataStartInFullMsgOffset + exchangeNameOffsetInRData} exceeds remaining RDLENGTH (${rdataBuffer.length - exchangeNameOffsetInRData}).`,
            );
          }
          return { preference, exchange: exchangeNameResult.name };
        case RR_TYPE_TXT: {
          const texts: string[] = [];
          let currentRdataOffset = 0;
          while (currentRdataOffset < rdataBuffer.length) {
            const len = readUint8(rdataBuffer, currentRdataOffset);
            currentRdataOffset++;
            if (currentRdataOffset + len > rdataBuffer.length) {
              // Malformed TXT string, length exceeds RDATA
              throw new PcapDecodingError(
                `TXT record character string length ${len} at offset ${currentRdataOffset - 1} in RDATA exceeds RDATA bounds.`,
              );
            }
            texts.push(rdataBuffer.toString('utf8', currentRdataOffset, currentRdataOffset + len));
            currentRdataOffset += len;
          }
          return texts;
        }
        case RR_TYPE_SOA: {
          let consumedInRData = 0;

          // MNAME
          if (consumedInRData >= rdataBuffer.length) {
            // Not enough data even for the start of MNAME
            throw new PcapDecodingError(
              `SOA RDATA too short at offset ${rdataStartInFullMsgOffset + consumedInRData} for MNAME. RDATA length: ${rdataBuffer.length}, available: ${rdataBuffer.length - consumedInRData}, needed at least 1 byte for name.`,
            );
          }
          const mnameResult = this._parseQName(
            fullMessageBuffer,
            rdataStartInFullMsgOffset + consumedInRData,
            messageStartOffset,
          );
          // mnameResult.bytesRead is the length of the MNAME representation in the buffer.
          // This check needs to be careful: mnameResult.bytesRead is how many bytes _parseQName *would* read
          // from fullMessageBuffer starting at rdataStartInFullMsgOffset + consumedInRData.
          // We need to ensure this doesn't imply reading beyond rdataBuffer.
          if (mnameResult.bytesRead > rdataBuffer.length - consumedInRData) {
            throw new PcapDecodingError(
              `SOA RDATA MNAME parsing at offset ${rdataStartInFullMsgOffset + consumedInRData} would exceed RDATA bounds. RDATA available for MNAME: ${rdataBuffer.length - consumedInRData}, MNAME's on-wire representation length: ${mnameResult.bytesRead}.`,
            );
          }
          consumedInRData += mnameResult.bytesRead;

          // RNAME
          if (consumedInRData >= rdataBuffer.length) {
            // Not enough data for the start of RNAME
            throw new PcapDecodingError(
              `SOA RDATA too short at offset ${rdataStartInFullMsgOffset + consumedInRData} for RNAME. RDATA length: ${rdataBuffer.length}, consumed for MNAME: ${mnameResult.bytesRead}, available for RNAME: ${rdataBuffer.length - consumedInRData}, needed at least 1 byte.`,
            );
          }
          const rnameResult = this._parseQName(
            fullMessageBuffer,
            rdataStartInFullMsgOffset + consumedInRData,
            messageStartOffset,
          );
          if (rnameResult.bytesRead > rdataBuffer.length - consumedInRData) {
            throw new PcapDecodingError(
              `SOA RDATA RNAME parsing at offset ${rdataStartInFullMsgOffset + consumedInRData} would exceed RDATA bounds. RDATA available for RNAME: ${rdataBuffer.length - consumedInRData}, RNAME's on-wire representation length: ${rnameResult.bytesRead}.`,
            );
          }
          consumedInRData += rnameResult.bytesRead;

          const SOA_FIXED_FIELDS_LENGTH = 20; // Serial, Refresh, Retry, Expire, Minimum (5 * 4 bytes)
          if (consumedInRData + SOA_FIXED_FIELDS_LENGTH > rdataBuffer.length) {
            throw new PcapDecodingError(
              `SOA RDATA too short for fixed numeric fields. Started at RDATA offset ${consumedInRData} (absolute offset ${rdataStartInFullMsgOffset + consumedInRData}). RDATA total length: ${rdataBuffer.length}, consumed for MNAME/RNAME: ${consumedInRData}. Needed ${SOA_FIXED_FIELDS_LENGTH} bytes for numeric fields, available: ${rdataBuffer.length - consumedInRData}.`,
            );
          }

          const serial = readUint32BE(rdataBuffer, consumedInRData);
          consumedInRData += 4;
          const refresh = readUint32BE(rdataBuffer, consumedInRData);
          consumedInRData += 4;
          const retry = readUint32BE(rdataBuffer, consumedInRData);
          consumedInRData += 4;
          const expire = readUint32BE(rdataBuffer, consumedInRData);
          consumedInRData += 4;
          const minimum = readUint32BE(rdataBuffer, consumedInRData);
          // consumedInRData += 4; // Not needed for the last field

          return {
            mname: mnameResult.name,
            rname: rnameResult.name,
            serial,
            refresh,
            retry,
            expire,
            minimum,
          };
        }
        default:
          // Unknown type or type not specifically handled, return raw buffer
          return rdataBuffer;
      }
    } catch (error) {
      // If parsing RDATA fails (e.g., BufferOutOfBoundsError from _parseQName if a name
      // within RDATA is malformed, or PcapDecodingError from TXT/label parsing).
      if (
        error instanceof BufferOutOfBoundsError ||
        error instanceof PcapDecodingError
      ) {
        // Intended fallback: If specific RDATA parsing fails due to malformed content
        // (e.g., bad label in CNAME, TXT string length mismatch, SOA fields truncated),
        // return the raw RDATA buffer. This makes the decoder resilient to some forms of bad data.
        return rdataBuffer;
      }
      // Re-throw unexpected errors not caught by the specific parsing logic.
      throw error;
    }
    // Fallback for types that had specific parsing but failed an internal check (e.g. length check)
    // and used 'break' to exit the switch.
    return rdataBuffer;
  }
}
