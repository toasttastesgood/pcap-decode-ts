/**
 * Base class for all custom errors in the pcap-decoder-ts library.
 */
export class PcapError extends Error {
  /**
   * @param message - The error message.
   */
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
    // Set the prototype explicitly.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Error thrown when there is an issue parsing PCAP file structures.
 */
export class PcapParsingError extends PcapError {
  constructor(message: string) {
    super(message);
  }
}

/**
 * Error thrown when there is an issue decoding packet data.
 */
export class PcapDecodingError extends PcapError {
  /**
   * @param message - The error message.
   */
  constructor(message: string) {
    super(message);
  }
}

/**
 * Error thrown when an operation attempts to read beyond the bounds of a buffer.
 */
export class BufferOutOfBoundsError extends PcapParsingError {
  /**
   * @param message - The error message. Defaults to "Attempted to read beyond buffer bounds".
   */
  constructor(message: string = 'Attempted to read beyond buffer bounds') {
    super(message);
  }
}

/**
 * Error thrown for invalid or unsupported PCAP file formats.
 */
export class InvalidFileFormatError extends PcapParsingError {
  constructor(message: string) {
    super(message);
  }
}

/**
 * Error thrown for unsupported link layer types.
 */
export class UnsupportedLinktypeError extends PcapDecodingError {
  /**
   * @param linktype - The unsupported link layer type number.
   */
  constructor(linktype: number) {
    super(`Unsupported linktype: ${linktype}`);
  }
}
