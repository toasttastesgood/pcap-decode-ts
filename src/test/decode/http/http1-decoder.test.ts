import { describe, it, expect, beforeEach } from 'vitest';
import { HTTP1Decoder } from '../../../decode/http/http1-decoder';
import { PcapDecodingError } from '../../../errors'; // Import PcapDecodingError
import { HTTP1RequestLayer, HTTP1ResponseLayer } from '../../../decode/http/http1-layer';
import { Buffer } from 'buffer';

describe('HTTP1Decoder', () => {
  let decoder: HTTP1Decoder;

  beforeEach(() => {
    decoder = new HTTP1Decoder();
  });

  it('should have the correct protocolName', () => {
    expect(decoder.protocolName).toBe('HTTP/1.x');
  });

  describe('Request Parsing', () => {
    it('should correctly parse a simple GET request', () => {
      const rawRequest =
        'GET /test/path?query=1 HTTP/1.1\r\n' +
        'Host: example.com\r\n' +
        'User-Agent: TestClient/1.0\r\n' +
        'Accept: application/json\r\n' +
        '\r\n';
      const buffer = Buffer.from(rawRequest, 'ascii');
      const result = decoder.decode(buffer);

      expect(result).not.toBeNull();
      if (!result) return; // Type guard

      expect(result.protocolName).toBe('HTTP/1.x');
      expect(result.headerLength).toBe(buffer.length);
      expect(result.payload.length).toBe(0);

      const data = result.data as HTTP1RequestLayer;
      expect(data.type).toBe('request');
      expect(data.method).toBe('GET');
      expect(data.uri).toBe('/test/path?query=1');
      expect(data.version).toBe('HTTP/1.1');
      expect(data.headers).toEqual({
        host: 'example.com',
        'user-agent': 'TestClient/1.0',
        accept: 'application/json',
      });
      expect(data.body).toBeUndefined();
    });

    it('should correctly parse a POST request with a body', () => {
      const requestBody = '{"key":"value"}';
      const rawRequest =
        'POST /api/submit HTTP/1.1\r\n' +
        'Host: api.example.com\r\n' +
        'Content-Type: application/json\r\n' +
        `Content-Length: ${requestBody.length}\r\n` +
        '\r\n' +
        requestBody;
      const buffer = Buffer.from(rawRequest, 'ascii');
      const result = decoder.decode(buffer);

      expect(result).not.toBeNull();
      if (!result) return;

      expect(result.protocolName).toBe('HTTP/1.x');
      expect(result.headerLength).toBe(rawRequest.indexOf('\r\n\r\n') + 4);
      expect(result.payload.toString('ascii')).toBe(requestBody);

      const data = result.data as HTTP1RequestLayer;
      expect(data.type).toBe('request');
      expect(data.method).toBe('POST');
      expect(data.uri).toBe('/api/submit');
      expect(data.version).toBe('HTTP/1.1');
      expect(data.headers).toEqual({
        host: 'api.example.com',
        'content-type': 'application/json',
        'content-length': requestBody.length.toString(),
      });
      expect(data.body).toBeDefined();
      expect(data.body?.toString('ascii')).toBe(requestBody);
    });

    it('should handle request headers with leading/trailing whitespace in values', () => {
      const rawRequest =
        'GET / HTTP/1.1\r\n' +
        'Host: example.com\r\n' +
        'X-Custom-Header:  Value with spaces  \r\n' +
        '\r\n';
      const buffer = Buffer.from(rawRequest, 'ascii');
      const result = decoder.decode(buffer);
      if (!result) return;
      const data = result.data as HTTP1RequestLayer;
      expect(data.headers['x-custom-header']).toBe('Value with spaces');
    });
  });

  describe('Response Parsing', () => {
    it('should correctly parse a 200 OK response', () => {
      const rawResponse =
        'HTTP/1.1 200 OK\r\n' +
        'Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n' +
        'Server: Apache/2.2.14 (Win32)\r\n' +
        'Content-Type: text/html\r\n' +
        'Connection: Closed\r\n' +
        '\r\n';
      const buffer = Buffer.from(rawResponse, 'ascii');
      const result = decoder.decode(buffer);

      expect(result).not.toBeNull();
      if (!result) return;

      expect(result.protocolName).toBe('HTTP/1.x');
      expect(result.headerLength).toBe(buffer.length);
      expect(result.payload.length).toBe(0);

      const data = result.data as HTTP1ResponseLayer;
      expect(data.type).toBe('response');
      expect(data.version).toBe('HTTP/1.1');
      expect(data.statusCode).toBe(200);
      expect(data.reasonPhrase).toBe('OK');
      expect(data.headers).toEqual({
        date: 'Mon, 27 Jul 2009 12:28:53 GMT',
        server: 'Apache/2.2.14 (Win32)',
        'content-type': 'text/html',
        connection: 'Closed',
      });
      expect(data.body).toBeUndefined();
    });

    it('should correctly parse a 404 Not Found response with a body', () => {
      const responseBody = 'Resource not available.';
      const rawResponse =
        'HTTP/1.0 404 Not Found\r\n' +
        'Content-Type: text/plain\r\n' +
        `Content-Length: ${responseBody.length}\r\n` +
        '\r\n' +
        responseBody;
      const buffer = Buffer.from(rawResponse, 'ascii');
      const result = decoder.decode(buffer);

      expect(result).not.toBeNull();
      if (!result) return;

      expect(result.protocolName).toBe('HTTP/1.x');
      expect(result.headerLength).toBe(rawResponse.indexOf('\r\n\r\n') + 4);
      expect(result.payload.toString('ascii')).toBe(responseBody);

      const data = result.data as HTTP1ResponseLayer;
      expect(data.type).toBe('response');
      expect(data.version).toBe('HTTP/1.0');
      expect(data.statusCode).toBe(404);
      expect(data.reasonPhrase).toBe('Not Found');
      expect(data.headers).toEqual({
        'content-type': 'text/plain',
        'content-length': responseBody.length.toString(),
      });
      expect(data.body).toBeDefined();
      expect(data.body?.toString('ascii')).toBe(responseBody);
    });

    it('should parse status line with no reason phrase', () => {
      const rawResponse = 'HTTP/1.1 503\r\n\r\n'; // Some servers might omit reason phrase
      const buffer = Buffer.from(rawResponse, 'ascii');
      const result = decoder.decode(buffer);
      if (!result) return;
      const data = result.data as HTTP1ResponseLayer;
      expect(data.statusCode).toBe(503);
      expect(data.reasonPhrase).toBe(''); // Or handle as per RFC if it specifies a default
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should throw PcapDecodingError for incomplete headers (missing blank line)', () => {
      const rawRequest = 'GET / HTTP/1.1\r\nHost: example.com'; // No \r\n\r\n
      const buffer = Buffer.from(rawRequest, 'ascii');
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow(
        'Incomplete HTTP headers: Missing blank line separator (\\r\\n\\r\\n).',
      );
    });

    it('should throw PcapDecodingError for an empty message', () => {
      const buffer = Buffer.from('\r\n\r\n', 'ascii'); // Only separators
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow('Missing first line of HTTP message (request/status line).');
    });
    it('should throw PcapDecodingError for message with only first line and no headers', () => {
      const buffer = Buffer.from('GET / HTTP/1.1\r\n\r\n', 'ascii');
      const result = decoder.decode(buffer);
      if (!result) return;
      const data = result.data as HTTP1RequestLayer;
      expect(data.method).toBe('GET');
      expect(data.headers).toEqual({}); // Should parse with empty headers
    });

    it('should throw PcapDecodingError for malformed first line', () => {
      const rawMessage = 'INVALID LINE\r\nHost: example.com\r\n\r\n';
      const buffer = Buffer.from(rawMessage, 'ascii');
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow(
        'Malformed HTTP message: Unable to parse first line "INVALID LINE" as a valid HTTP/1.x request or status line.',
      );
    });

    it('should throw PcapDecodingError for invalid header line', () => {
      const rawMessage =
        'GET / HTTP/1.1\r\n' +
        'Host example.com\r\n' + // Missing colon
        '\r\n';
      const buffer = Buffer.from(rawMessage, 'ascii');
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow(
        'Invalid HTTP header line (missing colon separator): "Host example.com"',
      );
    });

    it('should handle buffer with only body correctly (after headers)', () => {
      // This scenario implies headers were already processed, and we're given the body part.
      // The current decode expects full headers. This test might be more for a body-specific parser.
      // For HTTP1Decoder, it would fail as it expects headers.
      const bodyOnly = 'just body data';
      const buffer = Buffer.from(bodyOnly, 'ascii');
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError); // Expects headers
    });
  });

  describe('nextProtocolType', () => {
    it('should return null', () => {
      // Dummy data, as it's not used by nextProtocolType for HTTP
      const dummyLayer: HTTP1RequestLayer = {
        type: 'request',
        method: 'GET',
        uri: '/',
        version: 'HTTP/1.1',
        headers: {},
      };
      expect(decoder.nextProtocolType(dummyLayer)).toBeNull();
    });
  });
});
