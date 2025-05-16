/**
 * Represents the data parsed from an HTTP/1.x layer.
 */
export interface HTTP1RequestLayer {
  /** Indicates that this is an HTTP request. */
  type: 'request';
  /** The HTTP method (e.g., "GET", "POST", "PUT"). */
  method: string;
  /** The request URI (e.g., "/index.html?query=param"). */
  uri: string;
  /** The HTTP version string (e.g., "HTTP/1.1"). */
  version: string;
  /** A record of HTTP headers, where keys are lowercase header names. */
  headers: Record<string, string>;
  /** The optional HTTP request body. */
  body?: Buffer;
}

/**
 * Represents the data parsed from an HTTP/1.x response layer.
 */
export interface HTTP1ResponseLayer {
  /** Indicates that this is an HTTP response. */
  type: 'response';
  /** The HTTP version string (e.g., "HTTP/1.1"). */
  version: string;
  /** The HTTP status code (e.g., 200, 404, 500). */
  statusCode: number;
  /** The HTTP reason phrase associated with the status code (e.g., "OK", "Not Found"). */
  reasonPhrase: string;
  /** A record of HTTP headers, where keys are lowercase header names. */
  headers: Record<string, string>;
  /** The optional HTTP response body. */
  body?: Buffer;
}

/**
 * Represents a decoded HTTP/1.x layer, which can be either a request or a response.
 */
export type HTTP1Layer = HTTP1RequestLayer | HTTP1ResponseLayer;
