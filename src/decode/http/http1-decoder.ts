import { Decoder, DecoderOutputLayer } from '../decoder';
import { HTTP1Layer } from './http1-layer';
import { Buffer } from 'buffer'; // Node.js Buffer
import { PcapDecodingError } from '../../errors';

/**
 * Decodes HTTP/1.x protocol messages.
 */
export class HTTP1Decoder implements Decoder<HTTP1Layer> {
  public readonly protocolName = 'HTTP/1.x';

  /**
   * Decodes the provided buffer into an HTTP/1.x layer.
   * @param buffer The raw byte buffer containing the HTTP message.
   * @returns A DecodedPacketLayer object if decoding is successful.
   * @throws PcapDecodingError if the buffer is malformed or if headers are incomplete.
   */
  public decode(buffer: Buffer): DecoderOutputLayer<HTTP1Layer> | null {
    const endOfHeadersMarker = '\r\n\r\n';
    const headerEndIndex = buffer.indexOf(endOfHeadersMarker);

    if (headerEndIndex === -1) {
      // Incomplete headers, cannot parse
      // As per instructions, throwing an error for incomplete headers is acceptable.
      // However, returning null might be more aligned with the Decoder interface
      // if "incomplete" means "not enough data yet, try again later".
      // For now, let's throw as per specific instruction for this task.
      throw new PcapDecodingError(
        'Incomplete HTTP headers: Missing blank line separator (\\r\\n\\r\\n).',
      );
    }

    const headerText = buffer.subarray(0, headerEndIndex).toString('ascii');
    const bodyBuffer = buffer.subarray(headerEndIndex + endOfHeadersMarker.length);

    const lines = headerText.split('\r\n');
    // If headerText is empty, lines will be [''].
    // If headerText is just "\r\n", lines will be ['', ''].
    // We are interested if there's no actual first line content.
    if (lines.length === 0 || (lines.length === 1 && lines[0].trim() === '')) {
      throw new PcapDecodingError('Missing first line of HTTP message (request/status line).');
    }
 
    const firstLine = lines.shift() as string; // We've ensured lines[0] exists and shift won't return undefined.
 
    const headers: Record<string, string> = {};
    let lastHeaderName: string | null = null;
    for (const line of lines) {
      if (line.startsWith(' ') || line.startsWith('\t')) {
        // Obsolete line folding
        if (lastHeaderName && headers[lastHeaderName]) {
          headers[lastHeaderName] += ' ' + line.trim(); // Append with a space
        } else {
          // Folded line without a preceding header field. This is malformed.
          throw new PcapDecodingError(
            `Invalid HTTP header: Obsolete line folding observed without a preceding valid header field: "${line}"`,
          );
        }
      } else {
        const separatorIndex = line.indexOf(':');
        if (separatorIndex > 0) {
          const name = line.substring(0, separatorIndex).trim().toLowerCase();
          const value = line.substring(separatorIndex + 1).trim();
          if (headers[name]) {
            // Simple append for duplicate headers, as per RFC 7230 recommendation for combining.
            // "a recipient MAY combine multiple header fields with the same field name into one comma-separated list"
            headers[name] += ', ' + value;
          } else {
            headers[name] = value;
          }
          lastHeaderName = name;
        } else if (line.trim() !== '') {
          // Invalid header line
          throw new PcapDecodingError(
            `Invalid HTTP header line (missing colon separator or malformed): "${line}"`,
          );
        } else {
          // Empty line, possibly between header blocks if not for \r\n\r\n, but split should handle this.
          // Or, an empty line that's not part of folding and not a valid header.
          lastHeaderName = null; // Reset last header name on non-folded, non-header lines
        }
      }
    }

    // Try to parse as request: "METHOD URI VERSION"
    // e.g., "GET /index.html HTTP/1.1"
    const requestLineMatch = firstLine.match(/^([A-Z]+)\s+(\S+)\s+HTTP\/(\d\.\d)$/);
    if (requestLineMatch) {
      const [, method, uri, version] = requestLineMatch;
      const parsedLayer: HTTP1Layer = {
        type: 'request',
        method,
        uri,
        version: `HTTP/${version}`,
        headers,
        body: bodyBuffer.length > 0 ? bodyBuffer : undefined,
      };
      return {
        protocolName: this.protocolName,
        headerLength: headerEndIndex + endOfHeadersMarker.length,
        data: parsedLayer,
        payload: bodyBuffer, // In HTTP, the "payload" of the HTTP layer is the body
      };
    }

    // Try to parse as response: "VERSION STATUS_CODE REASON_PHRASE"
    // e.g., "HTTP/1.1 200 OK" or "HTTP/1.1 503"
    // Regex allows for optional space and reason phrase
    const statusLineMatch = firstLine.match(/^HTTP\/(\d\.\d)\s+(\d{3})(?:\s+(.*))?$/);
    if (statusLineMatch) {
      const [, version, statusCodeStr, reasonPhraseGroup] = statusLineMatch;
      const statusCode = parseInt(statusCodeStr, 10);
      const reasonPhrase = reasonPhraseGroup ? reasonPhraseGroup.trim() : ''; // Default to empty if not present
      const parsedLayer: HTTP1Layer = {
        type: 'response',
        version: `HTTP/${version}`,
        statusCode,
        reasonPhrase: reasonPhrase, // Already trimmed or empty
        headers,
        body: bodyBuffer.length > 0 ? bodyBuffer : undefined,
      };
      return {
        protocolName: this.protocolName,
        headerLength: headerEndIndex + endOfHeadersMarker.length,
        data: parsedLayer,
        payload: bodyBuffer,
      };
    }

    throw new PcapDecodingError(
      `Malformed HTTP message: Unable to parse first line "${firstLine}" as a valid HTTP/1.x request or status line.`,
    );
  }

  /**
   * HTTP is an application layer protocol, so it does not typically define a "next protocol"
   * in the same way network or transport layers do.
   * @param _decodedLayer The decoded HTTP layer data.
   * @returns Null, as HTTP is generally the final layer in this context.
   */
  public nextProtocolType(_decodedLayer: HTTP1Layer): number | string | null {
    return null;
  }
}
