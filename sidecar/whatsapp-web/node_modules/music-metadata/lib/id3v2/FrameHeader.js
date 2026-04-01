// lib/id3v2/FrameHeader.ts
import * as Token from 'token-types';
import * as util from '../common/Util.js';
import { UINT32SYNCSAFE } from './ID3v2Token.js';
import { textDecode } from '@borewit/text-codec';
import { Id3v2ContentError } from './FrameParser.js';
/**
 * Frame header length (bytes) depending on ID3v2 major version.
 */
export function getFrameHeaderLength(majorVer) {
    switch (majorVer) {
        case 2: return 6;
        case 3:
        case 4: return 10;
        default: throw makeUnexpectedMajorVersionError(majorVer);
    }
}
function readFrameFlags(b) {
    return {
        status: {
            tag_alter_preservation: util.getBit(b, 0, 6),
            file_alter_preservation: util.getBit(b, 0, 5),
            read_only: util.getBit(b, 0, 4)
        },
        format: {
            grouping_identity: util.getBit(b, 1, 7),
            compression: util.getBit(b, 1, 3),
            encryption: util.getBit(b, 1, 2),
            unsynchronisation: util.getBit(b, 1, 1),
            data_length_indicator: util.getBit(b, 1, 0)
        }
    };
}
/**
 * Factory: parse a frame header from its header bytes (6 for v2.2, 10 for v2.3/v2.4).
 *
 * Note: It only *parses* and does light validation. It does not read payload bytes.
 */
export function readFrameHeader(uint8Array, majorVer, warningCollector) {
    switch (majorVer) {
        case 2:
            return parseFrameHeaderV22(uint8Array, majorVer, warningCollector);
        case 3:
        case 4:
            return parseFrameHeaderV23V24(uint8Array, majorVer, warningCollector);
        default:
            throw makeUnexpectedMajorVersionError(majorVer);
    }
}
function parseFrameHeaderV22(uint8Array, majorVer, warningCollector) {
    const header = {
        id: textDecode(uint8Array.subarray(0, 3), 'ascii'),
        length: Token.UINT24_BE.get(uint8Array, 3)
    };
    if (!header.id.match(/^[A-Z0-9]{3}$/)) {
        warningCollector.addWarning(`Invalid ID3v2.${majorVer} frame-header-ID: ${header.id}`);
    }
    return header;
}
function parseFrameHeaderV23V24(uint8Array, majorVer, warningCollector) {
    const header = {
        id: textDecode(uint8Array.subarray(0, 4), 'ascii'),
        length: (majorVer === 4 ? UINT32SYNCSAFE : Token.UINT32_BE).get(uint8Array, 4),
        flags: readFrameFlags(uint8Array.subarray(8, 10))
    };
    if (!header.id.match(/^[A-Z0-9]{4}$/)) {
        warningCollector.addWarning(`Invalid ID3v2.${majorVer} frame-header-ID: ${header.id}`);
    }
    return header;
}
function makeUnexpectedMajorVersionError(majorVer) {
    throw new Id3v2ContentError(`Unexpected majorVer: ${majorVer}`);
}
