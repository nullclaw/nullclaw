import * as Token from 'token-types';
/**
 * Data portion of `CHAP` sub frame
 */
export const ChapterInfo = {
    len: 16,
    get: (buf, off) => {
        const startOffset = Token.UINT32_BE.get(buf, off + 8);
        const endOffset = Token.UINT32_BE.get(buf, off + 12);
        return {
            startTime: Token.UINT32_BE.get(buf, off),
            endTime: Token.UINT32_BE.get(buf, off + 4),
            startOffset: startOffset === 0xFFFFFFFF ? undefined : startOffset,
            endOffset: endOffset === 0xFFFFFFFF ? undefined : endOffset,
        };
    }
};
