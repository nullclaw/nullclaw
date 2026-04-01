import initDebug from 'debug';
import * as Token from 'token-types';
import * as util from '../common/Util.js';
import { AttachedPictureType, SyncTextHeader, TextEncodingToken, TextHeader } from './ID3v2Token.js';
import { Genres } from '../id3v1/ID3v1Parser.js';
import { makeUnexpectedFileContentError } from '../ParseError.js';
import { decodeUintBE } from '../common/Util.js';
import { ChapterInfo } from './ID3v2ChapterToken.js';
import { getFrameHeaderLength, readFrameHeader } from './FrameHeader.js';
const debug = initDebug('music-metadata:id3v2:frame-parser');
const defaultEnc = 'latin1'; // latin1 == iso-8859-1;
const urlEnc = { encoding: defaultEnc, bom: false };
export function parseGenre(origVal) {
    // match everything inside parentheses
    const genres = [];
    let code;
    let word = '';
    for (const c of origVal) {
        if (typeof code === 'string') {
            if (c === '(' && code === '') {
                word += '(';
                code = undefined;
            }
            else if (c === ')') {
                if (word !== '') {
                    genres.push(word);
                    word = '';
                }
                const genre = parseGenreCode(code);
                if (genre) {
                    genres.push(genre);
                }
                code = undefined;
            }
            else
                code += c;
        }
        else if (c === '(') {
            code = '';
        }
        else {
            word += c;
        }
    }
    if (word) {
        if (genres.length === 0 && word.match(/^\d*$/)) {
            word = parseGenreCode(word);
        }
        if (word) {
            genres.push(word);
        }
    }
    return genres;
}
function parseGenreCode(code) {
    if (code === 'RX')
        return 'Remix';
    if (code === 'CR')
        return 'Cover';
    if (code.match(/^\d*$/)) {
        return Genres[Number.parseInt(code, 10)];
    }
}
export class FrameParser {
    /**
     * Create id3v2 frame parser
     * @param major - Major version, e.g. (4) for  id3v2.4
     * @param warningCollector - Used to collect decode issue
     */
    constructor(major, warningCollector) {
        this.major = major;
        this.warningCollector = warningCollector;
    }
    readData(uint8Array, type, includeCovers) {
        if (uint8Array.length === 0) {
            this.warningCollector.addWarning(`id3v2.${this.major} header has empty tag type=${type}`);
            return;
        }
        const { encoding, bom } = TextEncodingToken.get(uint8Array, 0);
        const length = uint8Array.length;
        let offset = 0;
        let output = []; // ToDo
        const nullTerminatorLength = FrameParser.getNullTerminatorLength(encoding);
        let fzero;
        debug(`Parsing tag type=${type}, encoding=${encoding}, bom=${bom}`);
        switch (type !== 'TXXX' && type[0] === 'T' ? 'T*' : type) {
            case 'T*': // 4.2.1. Text information frames - details
            case 'GRP1': // iTunes-specific ID3v2 grouping field
            case 'GP1': // iTunes-specific ID3v2.2 grouping field
            case 'IPLS': // v2.3: Involved people list
            case 'MVIN':
            case 'MVNM':
            case 'PCS':
            case 'PCST': {
                let text;
                try {
                    text = FrameParser.trimNullPadding(util.decodeString(uint8Array.subarray(1), encoding));
                }
                catch (error) {
                    if (error instanceof Error) {
                        this.warningCollector.addWarning(`id3v2.${this.major} type=${type} header has invalid string value: ${error.message}`);
                        break;
                    }
                    throw error;
                }
                switch (type) {
                    case 'TMCL': // Musician credits list
                    case 'TIPL': // Involved people list
                    case 'IPLS': // Involved people list
                        output = FrameParser.functionList(this.splitValue(type, text));
                        break;
                    case 'TRK':
                    case 'TRCK':
                    case 'TPOS':
                    case 'TIT1':
                    case 'TIT2':
                    case 'TIT3':
                        output = text;
                        break;
                    case 'TCOM':
                    case 'TEXT':
                    case 'TOLY':
                    case 'TOPE':
                    case 'TPE1':
                    case 'TSRC':
                        // id3v2.3 defines that TCOM, TEXT, TOLY, TOPE & TPE1 values are separated by /
                        output = this.splitValue(type, text);
                        break;
                    case 'TCO':
                    case 'TCON':
                        output = this.splitValue(type, text).map(v => parseGenre(v)).reduce((acc, val) => acc.concat(val), []);
                        break;
                    case 'PCS':
                    case 'PCST':
                        // TODO: Why `default` not results `1` but `''`?
                        output = this.major >= 4 ? this.splitValue(type, text) : [text];
                        output = (Array.isArray(output) && output[0] === '') ? 1 : 0;
                        break;
                    default:
                        output = this.major >= 4 ? this.splitValue(type, text) : [text];
                }
                break;
            }
            case 'TXXX': {
                const idAndData = FrameParser.readIdentifierAndData(uint8Array.subarray(1), encoding);
                output = {
                    description: idAndData.id,
                    text: this.splitValue(type, util.decodeString(idAndData.data, encoding).replace(/\x00+$/, ''))
                };
                break;
            }
            case 'PIC':
            case 'APIC':
                if (includeCovers) {
                    const pic = {};
                    uint8Array = uint8Array.subarray(1);
                    switch (this.major) {
                        case 2:
                            pic.format = util.decodeString(uint8Array.subarray(0, 3), 'latin1'); // 'latin1'; // latin1 == iso-8859-1;
                            uint8Array = uint8Array.subarray(3);
                            break;
                        case 3:
                        case 4:
                            fzero = util.findZero(uint8Array, defaultEnc);
                            pic.format = util.decodeString(uint8Array.subarray(0, fzero), defaultEnc);
                            uint8Array = uint8Array.subarray(fzero + 1);
                            break;
                        default:
                            throw makeUnexpectedMajorVersionError(this.major);
                    }
                    pic.format = FrameParser.fixPictureMimeType(pic.format);
                    pic.type = AttachedPictureType[uint8Array[0]];
                    uint8Array = uint8Array.subarray(1);
                    fzero = util.findZero(uint8Array, encoding);
                    pic.description = util.decodeString(uint8Array.subarray(0, fzero), encoding);
                    uint8Array = uint8Array.subarray(fzero + nullTerminatorLength);
                    pic.data = uint8Array;
                    output = pic;
                }
                break;
            case 'CNT':
            case 'PCNT':
                output = decodeUintBE(uint8Array);
                break;
            case 'SYLT': {
                const syltHeader = SyncTextHeader.get(uint8Array, 0);
                uint8Array = uint8Array.subarray(SyncTextHeader.len);
                const result = {
                    descriptor: '',
                    language: syltHeader.language,
                    contentType: syltHeader.contentType,
                    timeStampFormat: syltHeader.timeStampFormat,
                    syncText: []
                };
                let readSyllables = false;
                while (uint8Array.length > 0) {
                    const nullStr = FrameParser.readNullTerminatedString(uint8Array, syltHeader.encoding);
                    uint8Array = uint8Array.subarray(nullStr.len);
                    if (readSyllables) {
                        const timestamp = Token.UINT32_BE.get(uint8Array, 0);
                        uint8Array = uint8Array.subarray(Token.UINT32_BE.len);
                        result.syncText.push({
                            text: nullStr.text,
                            timestamp
                        });
                    }
                    else {
                        result.descriptor = nullStr.text;
                        readSyllables = true;
                    }
                }
                output = result;
                break;
            }
            case 'ULT':
            case 'USLT':
            case 'COM':
            case 'COMM': {
                const textHeader = TextHeader.get(uint8Array, offset);
                offset += TextHeader.len;
                const descriptorStr = FrameParser.readNullTerminatedString(uint8Array.subarray(offset), textHeader.encoding);
                offset += descriptorStr.len;
                const textStr = FrameParser.readNullTerminatedString(uint8Array.subarray(offset), textHeader.encoding);
                const comment = {
                    language: textHeader.language,
                    descriptor: descriptorStr.text,
                    text: textStr.text
                };
                output = comment;
                break;
            }
            case 'UFID': {
                const ufid = FrameParser.readIdentifierAndData(uint8Array, defaultEnc);
                output = { owner_identifier: ufid.id, identifier: ufid.data };
                break;
            }
            case 'PRIV': { // private frame
                const priv = FrameParser.readIdentifierAndData(uint8Array, defaultEnc);
                output = { owner_identifier: priv.id, data: priv.data };
                break;
            }
            case 'POPM': { // Popularimeter
                uint8Array = uint8Array.subarray(offset);
                const emailStr = FrameParser.readNullTerminatedString(uint8Array, urlEnc);
                const email = emailStr.text;
                uint8Array = uint8Array.subarray(emailStr.len);
                if (uint8Array.length === 0) {
                    this.warningCollector.addWarning(`id3v2.${this.major} type=${type} POPM frame missing rating byte`);
                    output = { email, rating: 0, counter: undefined };
                    break;
                }
                const rating = Token.UINT8.get(uint8Array, 0);
                const counterBytes = uint8Array.subarray(Token.UINT8.len);
                output = {
                    email,
                    rating,
                    counter: counterBytes.length > 0 ? decodeUintBE(counterBytes) : undefined
                };
                break;
            }
            case 'GEOB': { // General encapsulated object
                // [encoding] <MIME> 0x00 <filename> 0x00/0x00 0x00 <description> 0x00/0x00 0x00 <data>
                const encoding = TextEncodingToken.get(uint8Array, 0);
                uint8Array = uint8Array.subarray(1);
                const mimeTypeStr = FrameParser.readNullTerminatedString(uint8Array, urlEnc);
                const mimeType = mimeTypeStr.text;
                uint8Array = uint8Array.subarray(mimeTypeStr.len);
                const filenameStr = FrameParser.readNullTerminatedString(uint8Array, encoding);
                const filename = filenameStr.text;
                uint8Array = uint8Array.subarray(filenameStr.len);
                const descriptionStr = FrameParser.readNullTerminatedString(uint8Array, encoding);
                const description = descriptionStr.text;
                uint8Array = uint8Array.subarray(descriptionStr.len);
                const geob = {
                    type: mimeType,
                    filename,
                    description,
                    data: uint8Array
                };
                output = geob;
                break;
            }
            // W-Frames:
            case 'WCOM':
            case 'WCOP':
            case 'WOAF':
            case 'WOAR':
            case 'WOAS':
            case 'WORS':
            case 'WPAY':
            case 'WPUB':
                // Decode URL
                output = FrameParser.readNullTerminatedString(uint8Array, urlEnc).text;
                break;
            case 'WXXX': {
                // [encoding] <description> 0x00/0x00 0x00 <url>
                const encoding = TextEncodingToken.get(uint8Array, 0);
                uint8Array = uint8Array.subarray(1);
                const descriptionStr = FrameParser.readNullTerminatedString(uint8Array, encoding);
                const description = descriptionStr.text;
                uint8Array = uint8Array.subarray(descriptionStr.len);
                // URL is always ISO-8859-1
                output = { description, url: FrameParser.trimNullPadding(util.decodeString(uint8Array, defaultEnc)) };
                break;
            }
            case 'WFD':
            case 'WFED': {
                const encoding = TextEncodingToken.get(uint8Array, 0);
                uint8Array = uint8Array.subarray(1);
                output = FrameParser.readNullTerminatedString(uint8Array, encoding).text;
                break;
            }
            case 'MCDI': {
                // Music CD identifier
                output = uint8Array.subarray(0, length);
                break;
            }
            // ID3v2 Chapters 1.0
            // https://mutagen-specs.readthedocs.io/en/latest/id3/id3v2-chapters-1.0.html#chapter-frame
            case 'CHAP': { //  // Chapter frame
                debug("Reading CHAP");
                fzero = util.findZero(uint8Array, defaultEnc);
                const chapter = {
                    label: util.decodeString(uint8Array.subarray(0, fzero), defaultEnc),
                    info: ChapterInfo.get(uint8Array, fzero + 1),
                    frames: new Map()
                };
                offset += fzero + 1 + ChapterInfo.len;
                while (offset < length) {
                    const subFrame = readFrameHeader(uint8Array.subarray(offset), this.major, this.warningCollector);
                    const headerSize = getFrameHeaderLength(this.major);
                    offset += headerSize;
                    const subOutput = this.readData(uint8Array.subarray(offset, offset + subFrame.length), subFrame.id, includeCovers);
                    offset += subFrame.length;
                    chapter.frames.set(subFrame.id, subOutput);
                }
                output = chapter;
                break;
            }
            // ID3v2 Chapters 1.0
            // https://mutagen-specs.readthedocs.io/en/latest/id3/id3v2-chapters-1.0.html#table-of-contents-frame
            case 'CTOC': { // Table of contents frame
                debug('Reading CTOC');
                // Element ID (null-terminated latin1)
                const idEnd = util.findZero(uint8Array, defaultEnc);
                const label = util.decodeString(uint8Array.subarray(0, idEnd), defaultEnc);
                offset = idEnd + 1;
                // Flags
                const flags = uint8Array[offset++];
                const topLevel = (flags & 0x02) !== 0;
                const ordered = (flags & 0x01) !== 0;
                // Child element IDs
                const entryCount = uint8Array[offset++];
                const childElementIds = [];
                for (let i = 0; i < entryCount && offset < length; i++) {
                    const end = util.findZero(uint8Array.subarray(offset), defaultEnc);
                    const childId = util.decodeString(uint8Array.subarray(offset, offset + end), defaultEnc);
                    childElementIds.push(childId);
                    offset += end + 1;
                }
                const toc = {
                    label,
                    flags: { topLevel, ordered },
                    childElementIds,
                    frames: new Map()
                };
                // Optional embedded sub-frames (e.g. TIT2) follow after the child list
                while (offset < length) {
                    const subFrame = readFrameHeader(uint8Array.subarray(offset), this.major, this.warningCollector);
                    const headerSize = getFrameHeaderLength(this.major);
                    offset += headerSize;
                    const subOutput = this.readData(uint8Array.subarray(offset, offset + subFrame.length), subFrame.id, includeCovers);
                    offset += subFrame.length;
                    toc.frames.set(subFrame.id, subOutput);
                }
                output = toc;
                break;
            }
            default:
                debug(`Warning: unsupported id3v2-tag-type: ${type}`);
                break;
        }
        return output;
    }
    static readNullTerminatedString(uint8Array, encoding) {
        const bomSize = encoding.bom ? 2 : 0;
        const originalLen = uint8Array.length;
        const valueArray = uint8Array.subarray(bomSize);
        const zeroIndex = util.findZero(valueArray, encoding.encoding);
        if (zeroIndex >= valueArray.length) {
            // No terminator found, decode full buffer remainder
            return {
                text: util.decodeString(valueArray, encoding.encoding),
                len: originalLen
            };
        }
        const txt = valueArray.subarray(0, zeroIndex);
        return {
            text: util.decodeString(txt, encoding.encoding),
            len: bomSize + zeroIndex + FrameParser.getNullTerminatorLength(encoding.encoding)
        };
    }
    static fixPictureMimeType(pictureType) {
        pictureType = pictureType.toLocaleLowerCase();
        switch (pictureType) {
            case 'jpg':
                return 'image/jpeg';
            case 'png':
                return 'image/png';
        }
        return pictureType;
    }
    /**
     * Converts TMCL (Musician credits list) or TIPL (Involved people list)
     * @param entries
     */
    static functionList(entries) {
        const res = {};
        for (let i = 0; i + 1 < entries.length; i += 2) {
            const names = entries[i + 1].split(',');
            res[entries[i]] = res[entries[i]] ? res[entries[i]].concat(names) : names;
        }
        return res;
    }
    /**
     * id3v2.4 defines that multiple T* values are separated by 0x00
     * id3v2.3 defines that TCOM, TEXT, TOLY, TOPE & TPE1 values are separated by /
     * @param tag - Tag name
     * @param text - Concatenated tag value
     * @returns Split tag value
     */
    splitValue(tag, text) {
        let values;
        if (this.major < 4) {
            values = text.split(/\x00/g);
            if (values.length > 1) {
                this.warningCollector.addWarning(`ID3v2.${this.major} ${tag} uses non standard null-separator.`);
            }
            else {
                values = text.split(/\//g);
            }
        }
        else {
            values = text.split(/\x00/g);
        }
        return FrameParser.trimArray(values);
    }
    static trimArray(values) {
        return values.map(value => FrameParser.trimNullPadding(value).trim());
    }
    static trimNullPadding(value) {
        let end = value.length;
        while (end > 0 && value.charCodeAt(end - 1) === 0) {
            end--;
        }
        return end === value.length ? value : value.slice(0, end);
    }
    static readIdentifierAndData(uint8Array, encoding) {
        const idStr = FrameParser.readNullTerminatedString(uint8Array, { encoding, bom: false });
        return { id: idStr.text, data: uint8Array.subarray(idStr.len) };
    }
    static getNullTerminatorLength(enc) {
        return enc.startsWith('utf-16') ? 2 : 1;
    }
}
export class Id3v2ContentError extends makeUnexpectedFileContentError('id3v2') {
}
function makeUnexpectedMajorVersionError(majorVer) {
    throw new Id3v2ContentError(`Unexpected majorVer: ${majorVer}`);
}
