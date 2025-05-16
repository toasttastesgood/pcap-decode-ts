import { Decoder, DecoderOutputLayer } from '../decoder';
import { DNSLayer, DNSFlags, DNSQuestion, DNSResourceRecord } from './dns-layer';
import { BufferOutOfBoundsError, PcapDecodingError } from '../../errors'; // Added PcapDecodingError
import { readUint16BE, readUint8, readUint32BE } from '../../utils/byte-readers'; // Added readUint32BE

const DNS_HEADER_LENGTH = 12;
const MAX_NAME_POINTER_RECURSION = 10; // To prevent infinite loops with bad compression pointers

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
      const length = readUint8(buffer, currentReadOffset); // Corrected function name
      if (length === 0) {
        // End of name
        currentReadOffset++;
        if (!followedPointer) bytesConsumedForThisName++;
        break;
      }

      if ((length & 0xc0) === 0xc0) {
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
        labels.push(pointedNameResult.name);
        currentReadOffset += 2; // Pointer is 2 bytes
        if (!followedPointer) bytesConsumedForThisName += 2;
        followedPointer = true; // After a pointer, subsequent bytes are not part of this name's length
        break; // Name is resolved by the pointer
      } else if ((length & 0xc0) === 0x00) {
        // Normal label
        currentReadOffset++;
        if (currentReadOffset + length > buffer.length) {
          throw new BufferOutOfBoundsError(
            `DNS label length ${length} at offset ${currentReadOffset - 1} exceeds buffer bounds (buffer length ${buffer.length}).`,
          );
        }
        labels.push(buffer.toString('ascii', currentReadOffset, currentReadOffset + length));
        currentReadOffset += length;
        if (!followedPointer) bytesConsumedForThisName += 1 + length;
      } else {
        // Invalid label type (e.g., 0x80 or 0x40 start bits are reserved/unused)
        throw new PcapDecodingError(
          `Invalid DNS label type: 0x${length.toString(16)} at offset ${currentReadOffset - 1}. First two bits must be 00 or 11.`,
        );
      }
    }

    if (currentReadOffset > buffer.length && labels.length === 0 && length !== 0) {
      // length check added
      throw new BufferOutOfBoundsError(
        `DNS QNAME parsing read past buffer end at offset ${nameOffset} without terminating null byte or valid pointer.`,
      );
    }

    return { name: labels.join('.'), bytesRead: bytesConsumedForThisName };
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

    const record: DNSResourceRecord = {
      NAME: nameResult.name,
      TYPE: type,
      CLASS: rrClass,
      TTL: ttl,
      RDLENGTH: rdLength,
      RDATA: rdata, // For now, RDATA is raw buffer. Specific parsing can be added.
    };

    return { record, bytesRead: currentReadOffset - rrOffset };
  }
}
