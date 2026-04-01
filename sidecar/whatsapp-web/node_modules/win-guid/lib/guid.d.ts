/**
 * Parse canonical GUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
 * into Windows / CFBF byte order.
 */
export declare function parseWindowsGuid(guid: string): Uint8Array;
export declare class Guid {
    readonly bytes: Uint8Array;
    constructor(bytes: Uint8Array);
    static fromString(guid: string): Guid;
    /**
     * Convert Windows / CFBF byte order into canonical GUID string:
     * xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
     */
    toString(): string;
    /**
     * Compare against a Uint8Array containing GUID bytes
     * in Windows / CFBF layout.
     */
    equals(buf: Uint8Array, offset?: number): boolean;
}
