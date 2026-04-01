export const asfParserLoader = {
    parserType: 'asf',
    extensions: ['.asf', '.wma', '.wmv'],
    mimeTypes: ['audio/ms-wma', 'video/ms-wmv', 'audio/ms-asf', 'video/ms-asf', 'application/vnd.ms-asf'],
    async load() {
        return (await import('./AsfParser.js')).AsfParser;
    }
};
