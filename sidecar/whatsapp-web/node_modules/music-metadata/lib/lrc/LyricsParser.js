import { LyricsContentType, TimestampFormat } from '../type.js';
// Shared timestamp regex for LRC format
const TIMESTAMP_REGEX = /\[(\d{2}):(\d{2})\.(\d{2,3})]/;
export function parseLyrics(input) {
    if (TIMESTAMP_REGEX.test(input)) {
        return parseLrc(input);
    }
    return toUnsyncedLyrics(input);
}
export function toUnsyncedLyrics(lyrics) {
    return {
        contentType: LyricsContentType.lyrics,
        timeStampFormat: TimestampFormat.notSynchronized,
        text: lyrics.trim(),
        syncText: [],
    };
}
/**
 * Parse LRC (Lyrics) formatted text
 * Ref: https://en.wikipedia.org/wiki/LRC_(file_format)
 * @param lrcString
 */
export function parseLrc(lrcString) {
    const lines = lrcString.split('\n');
    const syncText = [];
    for (const line of lines) {
        const match = line.match(TIMESTAMP_REGEX);
        if (match) {
            const minutes = Number.parseInt(match[1], 10);
            const seconds = Number.parseInt(match[2], 10);
            const ms = match[3].length === 3
                ? Number.parseInt(match[3], 10)
                : Number.parseInt(match[3], 10) * 10;
            const timestamp = (minutes * 60 + seconds) * 1000 + ms;
            const text = line.replace(TIMESTAMP_REGEX, '').trim();
            syncText.push({ timestamp, text });
        }
    }
    return {
        contentType: LyricsContentType.lyrics,
        timeStampFormat: TimestampFormat.milliseconds,
        text: syncText.map(line => line.text).join('\n'),
        syncText,
    };
}
