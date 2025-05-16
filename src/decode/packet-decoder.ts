import { Buffer } from 'buffer';
import { Decoder } from './decoder';
import { DecoderRegistry } from './decoder-registry';
import { logWarning } from '../utils/logger'; // Removed logError as we'll use logWarning for skippable errors
import { PcapError } from '../errors'; // For type checking specific errors
import { DecodedPacket, DecodedPacketLayer, RawPayloadLayer } from './packet-structures';

/**
 * Decodes a raw packet buffer into a structured DecodedPacket object.
 *
 * @param rawPacket - The raw packet data as a Buffer.
 * @param initialLinkLayerType - The link-layer type of the packet (e.g., from PCAP global header).
 * @param registry - An instance of DecoderRegistry to look up decoders.
 * @param timestamp - Optional timestamp of the packet.
 * @param originalLength - The original length of the packet on the wire.
 * @param capturedLength - The length of the packet data captured.
 * @param interfaceInfo - Optional interface information (e.g., from PCAPng Interface Description Block).
 * @returns A DecodedPacket object representing the structured data of the packet.
 */
export function decodePacket(
  rawPacket: Buffer,
  initialLinkLayerType: number,
  registry: DecoderRegistry,
  timestamp?: Date | number,
  originalLength?: number,
  capturedLength?: number,
  interfaceInfo?: unknown,
): DecodedPacket {
  const layers: (DecodedPacketLayer | RawPayloadLayer)[] = [];
  let currentBuffer = rawPacket;
  let currentProtocolType: number | string | undefined = initialLinkLayerType;
  let currentDecoder: Decoder<unknown> | undefined;

  while (currentProtocolType !== undefined && currentBuffer.length > 0) {
    currentDecoder = registry.getDecoder(currentProtocolType);

    if (!currentDecoder) {
      logWarning(
        `No decoder found for protocol type: ${currentProtocolType}. Remaining data will be treated as raw.`,
      );
      break; // Exit loop, remaining data will be added as RawPayloadLayer
    }

    try {
      const decodedLayerOutput = currentDecoder.decode(currentBuffer, {
        /* context if needed */
      });

      if (decodedLayerOutput === null) {
        logWarning(
          `Decoder for ${currentDecoder.protocolName || currentProtocolType} returned null. Stopping decode for this branch.`,
        );
        break; // Stop decoding this branch, remaining data will be raw.
      }

      // Construct the DecodedPacketLayer for the final DecodedPacket structure
      const layerForPacket: DecodedPacketLayer = {
        protocolName: decodedLayerOutput.protocolName,
        data: decodedLayerOutput.data,
        bytes: currentBuffer.subarray(0, decodedLayerOutput.headerLength), // Bytes of the header for this layer
        payload: decodedLayerOutput.payload, // Remaining buffer after this layer's header
      };
      layers.push(layerForPacket);

      if (layerForPacket.payload && layerForPacket.payload.length > 0) {
        currentBuffer = layerForPacket.payload;
        const nextProto = currentDecoder.nextProtocolType(decodedLayerOutput.data); // Pass data from decoded output
        currentProtocolType = nextProto === null ? undefined : nextProto;
      } else {
        // No more payload or next protocol indicated by this layer
        currentBuffer = Buffer.alloc(0); // Mark buffer as consumed
        currentProtocolType = undefined;
      }
    } catch (error: unknown) {
      const protocolNameForError =
        currentDecoder?.protocolName || currentProtocolType || 'Unknown Protocol';
      if (error instanceof PcapError) {
        // Check if it's one of our custom errors
        logWarning(
          `Error decoding protocol ${protocolNameForError} at current stage: ${error.message}. Remaining data for this protocol will be treated as raw.`,
        );
      } else {
        // Generic error
        let errorMessage = 'Unknown error';
        if (error instanceof Error) {
          errorMessage = error.message;
        }
        logWarning(
          `Unexpected error in protocol ${protocolNameForError}: ${errorMessage}. Remaining data for this protocol will be treated as raw.`,
        );
      }
      // Add remaining data as raw payload and stop further decoding for this packet
      if (currentBuffer.length > 0) {
        layers.push({
          protocolName: 'Raw Data',
          bytes: currentBuffer,
        });
      }
      currentBuffer = Buffer.alloc(0); // Mark buffer as consumed
      currentProtocolType = undefined; // Stop decoding
      break;
    }
  }

  // If there's still data left in the buffer after the loop (e.g., no decoder found, or last decoder didn't consume all)
  if (currentBuffer.length > 0) {
    layers.push({
      protocolName: 'Raw Data',
      bytes: currentBuffer,
    });
  }

  return {
    timestamp,
    originalLength: originalLength ?? rawPacket.length,
    capturedLength: capturedLength ?? rawPacket.length,
    interfaceInfo,
    layers,
  };
}
