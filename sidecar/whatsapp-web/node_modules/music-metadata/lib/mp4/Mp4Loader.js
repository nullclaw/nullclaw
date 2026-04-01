export const mp4ParserLoader = {
    parserType: 'mp4',
    extensions: ['.mp4', '.m4a', '.m4b', '.m4pa', 'm4v', 'm4r', '3gp', '.mov', '.movie', '.qt'],
    mimeTypes: ['audio/mp4', 'audio/m4a', 'video/m4v', 'video/mp4', 'video/quicktime'],
    async load() {
        return (await import('./MP4Parser.js')).MP4Parser;
    }
};
