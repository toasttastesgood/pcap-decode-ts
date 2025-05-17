import { describe, it, expect, beforeEach } from 'vitest';
import { HTTP1Decoder } from '../../../decode/http/http1-decoder';
import { PcapDecodingError } from '../../../errors';
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

    it('should correctly parse request headers with obsolete line folding', () => {
      const rawRequest =
        'GET / HTTP/1.1\r\n' +
        'Host: example.com\r\n' +
        'X-Folded-Header: part1\r\n' +
        ' part2\r\n' +
        '\tpart3 with tab\r\n' +
        'X-Other-Header: normal\r\n' +
        '\r\n';
      const buffer = Buffer.from(rawRequest, 'ascii');
      const result = decoder.decode(buffer);
      expect(result).not.toBeNull();
      if (!result) return;
      const data = result.data as HTTP1RequestLayer;
      expect(data.headers['x-folded-header']).toBe('part1 part2 part3 with tab');
      expect(data.headers['x-other-header']).toBe('normal');
    });

    it('should combine duplicate request headers with a comma', () => {
      const rawRequest =
        'GET / HTTP/1.1\r\n' +
        'Host: example.com\r\n' +
        'Set-Cookie: id=123\r\n' +
        'Set-Cookie: pref=abc\r\n' +
        'X-Single: solo\r\n' +
        '\r\n';
      const buffer = Buffer.from(rawRequest, 'ascii');
      const result = decoder.decode(buffer);
      expect(result).not.toBeNull();
      if (!result) return;
      const data = result.data as HTTP1RequestLayer;
      expect(data.headers['set-cookie']).toBe('id=123, pref=abc');
      expect(data.headers['x-single']).toBe('solo');
    });

    it('should parse HTTP/1.0 request', () => {
      const rawRequest = 'GET /old HTTP/1.0\r\nHost: example.com\r\n\r\n';
      const buffer = Buffer.from(rawRequest, 'ascii');
      const result = decoder.decode(buffer);
      expect(result).not.toBeNull();
      if (!result) return;
      const data = result.data as HTTP1RequestLayer;
      expect(data.version).toBe('HTTP/1.0');
      expect(data.method).toBe('GET');
    });

    it('should parse various request methods (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, TRACE, CONNECT)', () => {
      const methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT'];
      methods.forEach(method => {
        const rawRequest = `${method} /test HTTP/1.1\r\nHost: example.com\r\n\r\n`;
        const buffer = Buffer.from(rawRequest, 'ascii');
        const result = decoder.decode(buffer);
        expect(result).not.toBeNull();
        if (!result) return;
        const data = result.data as HTTP1RequestLayer;
        expect(data.method).toBe(method);
        expect(data.uri).toBe('/test');
        if (method === 'HEAD') {
          expect(data.body).toBeUndefined();
        }
      });
    });

    it('should handle request with Content-Length: 0 and empty body', () => {
      const rawRequest =
        'POST /empty HTTP/1.1\r\n' +
        'Host: example.com\r\n' +
        'Content-Length: 0\r\n' +
        '\r\n';
      const buffer = Buffer.from(rawRequest, 'ascii');
      const result = decoder.decode(buffer);
      expect(result).not.toBeNull();
      if (!result) return;
      const data = result.data as HTTP1RequestLayer;
      expect(data.body).toBeUndefined();
      expect(result.payload.length).toBe(0);
    });

    it('should parse request headers with no value', () => {
      const rawRequest =
        'GET / HTTP/1.1\r\n' +
        'Host: example.com\r\n' +
        'X-Empty-Value:\r\n' +
        'X-Another: present\r\n' +
        '\r\n';
      const buffer = Buffer.from(rawRequest, 'ascii');
      const result = decoder.decode(buffer);
      expect(result).not.toBeNull();
      if (!result) return;
      const data = result.data as HTTP1RequestLayer;
      expect(data.headers['x-empty-value']).toBe('');
      expect(data.headers['x-another']).toBe('present');
    });

    it('should handle case-insensitive header names for requests', () => {
      const rawRequest =
        'GET / HTTP/1.1\r\n' +
        'hOsT: example.com\r\n' +
        'CoNtEnT-TyPe: application/json\r\n' +
        '\r\n';
      const buffer = Buffer.from(rawRequest, 'ascii');
      const result = decoder.decode(buffer);
      expect(result).not.toBeNull();
      if (!result) return;
      const data = result.data as HTTP1RequestLayer;
      expect(data.headers['host']).toBe('example.com');
      expect(data.headers['content-type']).toBe('application/json');
    });

    it('should correctly parse request line with extra spaces between components', () => {
      const rawRequest = 'GET   /test   HTTP/1.1\r\nHost: example.com\r\n\r\n';
      const buffer = Buffer.from(rawRequest, 'ascii');
      const result = decoder.decode(buffer);
      expect(result).not.toBeNull();
      if (!result) return;
      const data = result.data as HTTP1RequestLayer;
      expect(data.method).toBe('GET');
      expect(data.uri).toBe('/test');
      expect(data.version).toBe('HTTP/1.1');
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
      const rawResponse = 'HTTP/1.1 503\r\n\r\n';
      const buffer = Buffer.from(rawResponse, 'ascii');
      const result = decoder.decode(buffer);
      expect(result).not.toBeNull();
      if (!result) return;
      const data = result.data as HTTP1ResponseLayer;
      expect(data.statusCode).toBe(503);
      expect(data.reasonPhrase).toBe('');
    });

    it('should parse HTTP/1.0 response', () => {
      const rawResponse = 'HTTP/1.0 200 OK\r\nServer: OldServer/1.0\r\n\r\n';
      const buffer = Buffer.from(rawResponse, 'ascii');
      const result = decoder.decode(buffer);
      expect(result).not.toBeNull();
      if (!result) return;
      const data = result.data as HTTP1ResponseLayer;
      expect(data.version).toBe('HTTP/1.0');
      expect(data.statusCode).toBe(200);
    });

    it('should handle response with Content-Length: 0 and empty body', () => {
      const rawResponse =
        'HTTP/1.1 204 No Content\r\n' +
        'Content-Length: 0\r\n' +
        '\r\n';
      const buffer = Buffer.from(rawResponse, 'ascii');
      const result = decoder.decode(buffer);
      expect(result).not.toBeNull();
      if (!result) return;
      const data = result.data as HTTP1ResponseLayer;
      expect(data.statusCode).toBe(204);
      expect(data.body).toBeUndefined();
      expect(result.payload.length).toBe(0);
    });

    it('should parse response headers with obsolete line folding', () => {
      const rawResponse =
        'HTTP/1.1 200 OK\r\n' +
        'Content-Type: text/plain\r\n' +
        'X-Folded-Response-Header: value1\r\n' +
        ' value2\r\n' +
        '\tvalue3\r\n' +
        '\r\n';
      const buffer = Buffer.from(rawResponse, 'ascii');
      const result = decoder.decode(buffer);
      expect(result).not.toBeNull();
      if (!result) return;
      const data = result.data as HTTP1ResponseLayer;
      expect(data.headers['x-folded-response-header']).toBe('value1 value2 value3');
    });

    it('should combine duplicate response headers with a comma', () => {
      const rawResponse =
        'HTTP/1.1 200 OK\r\n' +
        'Warning: 199 Miscellaneous warning\r\n' +
        'Warning: 199 Another warning\r\n' +
        '\r\n';
      const buffer = Buffer.from(rawResponse, 'ascii');
      const result = decoder.decode(buffer);
      expect(result).not.toBeNull();
      if (!result) return;
      const data = result.data as HTTP1ResponseLayer;
      expect(data.headers['warning']).toBe('199 Miscellaneous warning, 199 Another warning');
    });

    it('should parse response headers with no value', () => {
      const rawResponse =
        'HTTP/1.1 200 OK\r\n' +
        'X-Empty-Resp-Value:\r\n' +
        'X-Normal-Resp: ok\r\n' +
        '\r\n';
      const buffer = Buffer.from(rawResponse, 'ascii');
      const result = decoder.decode(buffer);
      expect(result).not.toBeNull();
      if (!result) return;
      const data = result.data as HTTP1ResponseLayer;
      expect(data.headers['x-empty-resp-value']).toBe('');
      expect(data.headers['x-normal-resp']).toBe('ok');
    });

    it('should handle case-insensitive header names for responses', () => {
      const rawResponse =
        'HTTP/1.1 200 OK\r\n' +
        'sErVeR: MyServer/1.0\r\n' +
        'cOnTeNt-LeNgTh: 0\r\n' +
        '\r\n';
      const buffer = Buffer.from(rawResponse, 'ascii');
      const result = decoder.decode(buffer);
      expect(result).not.toBeNull();
      if (!result) return;
      const data = result.data as HTTP1ResponseLayer;
      expect(data.headers['server']).toBe('MyServer/1.0');
      expect(data.headers['content-length']).toBe('0');
    });

    it('should correctly parse status line with extra spaces between components', () => {
      const rawResponse = 'HTTP/1.1  200   OK\r\nServer: Test\r\n\r\n';
      const buffer = Buffer.from(rawResponse, 'ascii');
      const result = decoder.decode(buffer);
      expect(result).not.toBeNull();
      if (!result) return;
      const data = result.data as HTTP1ResponseLayer;
      expect(data.version).toBe('HTTP/1.1');
      expect(data.statusCode).toBe(200);
      expect(data.reasonPhrase).toBe('OK');
    });

    it('should parse various status codes', () => {
      const statuses = [
        { code: 201, phrase: 'Created' },
        { code: 202, phrase: 'Accepted' },
        { code: 301, phrase: 'Moved Permanently' },
        { code: 302, phrase: 'Found' },
        { code: 400, phrase: 'Bad Request' },
        { code: 401, phrase: 'Unauthorized' },
        { code: 403, phrase: 'Forbidden' },
        { code: 500, phrase: 'Internal Server Error' },
        { code: 502, phrase: 'Bad Gateway' },
      ];
      statuses.forEach(status => {
        const rawResponse = `HTTP/1.1 ${status.code} ${status.phrase}\r\n\r\n`;
        const buffer = Buffer.from(rawResponse, 'ascii');
        const result = decoder.decode(buffer);
        expect(result).not.toBeNull();
        if (!result) return;
        const data = result.data as HTTP1ResponseLayer;
        expect(data.statusCode).toBe(status.code);
        expect(data.reasonPhrase).toBe(status.phrase);
      });
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

    it('should throw PcapDecodingError for an empty message (only CRLFCRLF)', () => {
      const buffer = Buffer.from('\r\n\r\n', 'ascii');
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow('Missing first line of HTTP message (request/status line).');
    });
    
    it('should throw PcapDecodingError for an entirely empty buffer', () => {
      const buffer = Buffer.from('', 'ascii');
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow('Incomplete HTTP headers: Missing blank line separator (\\r\\n\\r\\n).');
    });

    it('should correctly parse a message with only first line and no headers', () => {
      const buffer = Buffer.from('GET / HTTP/1.1\r\n\r\n', 'ascii');
      const result = decoder.decode(buffer);
      expect(result).not.toBeNull();
      if (!result) return;
      const data = result.data as HTTP1RequestLayer;
      expect(data.method).toBe('GET');
      expect(data.headers).toEqual({});
    });

    it('should throw PcapDecodingError for malformed first line (not request or response)', () => {
      const rawMessage = 'INVALID LINE\r\nHost: example.com\r\n\r\n';
      const buffer = Buffer.from(rawMessage, 'ascii');
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow(
        'Malformed HTTP message: Unable to parse first line "INVALID LINE" as a valid HTTP/1.x request or status line.',
      );
    });

    it('should throw PcapDecodingError for invalid header line (missing colon)', () => {
      const rawMessage =
        'GET / HTTP/1.1\r\n' +
        'Host example.com\r\n' + // Missing colon
        '\r\n';
      const buffer = Buffer.from(rawMessage, 'ascii');
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow(
        'Invalid HTTP header line (missing colon separator or malformed): "Host example.com"',
      );
    });
    
    it('should throw PcapDecodingError for invalid header line (empty header name before colon)', () => {
      const rawMessage = 
        'GET / HTTP/1.1\r\n' +
        ': emptyname\r\n' +
        '\r\n';
      const buffer = Buffer.from(rawMessage, 'ascii');
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow(
        'Invalid HTTP header line (missing colon separator or malformed): ": emptyname"',
      );
    });

    it('should throw PcapDecodingError for invalid obsolete line folding (no preceding header)', () => {
      const rawRequest =
        'GET / HTTP/1.1\r\n' +
        ' Host: example.com\r\n' + // Folded line without preceding header
        'X-Normal-Header: value\r\n' +
        '\r\n';
      const buffer = Buffer.from(rawRequest, 'ascii');
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow(
        'Invalid HTTP header: Obsolete line folding observed without a preceding valid header field: " Host: example.com"',
      );
    });
    
    it('should throw PcapDecodingError for folded line after an invalid header (error on invalid header first)', () => {
      const rawRequest = 
        'GET / HTTP/1.1\r\n' +
        'InvalidHeaderNoColon\r\n' + // This line is invalid
        ' FoldedLine\r\n' + // This line would be an invalid fold if the previous was valid
        '\r\n';
      const buffer = Buffer.from(rawRequest, 'ascii');
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow( // The error should be for the first problematic line
        'Invalid HTTP header line (missing colon separator or malformed): "InvalidHeaderNoColon"',
      );
    });

    it('should ignore buffer with only body data (throws due to missing headers)', () => {
      const bodyOnly = 'just body data';
      const buffer = Buffer.from(bodyOnly, 'ascii');
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      // This will fail because it's looking for \r\n\r\n to delimit headers
      expect(() => decoder.decode(buffer)).toThrow('Incomplete HTTP headers: Missing blank line separator (\\r\\n\\r\\n).');
    });

    it('should throw PcapDecodingError for request line with missing method', () => {
      const rawRequest = '/test HTTP/1.1\r\nHost: example.com\r\n\r\n';
      const buffer = Buffer.from(rawRequest, 'ascii');
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow(/Malformed HTTP message: Unable to parse first line/);
    });

    it('should throw PcapDecodingError for request line with missing URI', () => {
      const rawRequest = 'GET HTTP/1.1\r\nHost: example.com\r\n\r\n';
      const buffer = Buffer.from(rawRequest, 'ascii');
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow(/Malformed HTTP message: Unable to parse first line/);
    });

    it('should throw PcapDecodingError for request line with missing version', () => {
      const rawRequest = 'GET /test\r\nHost: example.com\r\n\r\n';
      const buffer = Buffer.from(rawRequest, 'ascii');
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow(/Malformed HTTP message: Unable to parse first line/);
    });

    it('should throw PcapDecodingError for status line with missing version', () => {
      const rawResponse = '200 OK\r\nServer: Test\r\n\r\n';
      const buffer = Buffer.from(rawResponse, 'ascii');
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow(/Malformed HTTP message: Unable to parse first line/);
    });

    it('should throw PcapDecodingError for status line with missing status code', () => {
      const rawResponse = 'HTTP/1.1 OK\r\nServer: Test\r\n\r\n';
      const buffer = Buffer.from(rawResponse, 'ascii');
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow(/Malformed HTTP message: Unable to parse first line/);
    });

    it('should throw PcapDecodingError for status line with non-numeric status code', () => {
      const rawResponse = 'HTTP/1.1 ABC OK\r\nServer: Test\r\n\r\n';
      const buffer = Buffer.from(rawResponse, 'ascii');
      expect(() => decoder.decode(buffer)).toThrow(PcapDecodingError);
      expect(() => decoder.decode(buffer)).toThrow(/Malformed HTTP message: Unable to parse first line/);
    });
  });

  describe('nextProtocolType', () => {
    it('should return null', () => {
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
