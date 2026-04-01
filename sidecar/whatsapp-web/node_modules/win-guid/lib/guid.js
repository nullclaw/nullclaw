/**
 * Parse canonical GUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
 * into Windows / CFBF byte order.
 */
export function parseWindowsGuid(guid) {
    let s = guid.trim();
    // Keep validation readable and strict, avoid lowercasing allocations
    if (s.length !== 36 ||
        s[8] !== "-" ||
        s[13] !== "-" ||
        s[18] !== "-" ||
        s[23] !== "-") {
        throw new Error(`Invalid GUID format: ${guid}`);
    }
    let v;
    const out = new Uint8Array(16);
    // Data1: 8 hex, uint32 little-endian
    v = parseInt(s.slice(0, 8), 16);
    out[0] = v & 0xff;
    out[1] = (v >>> 8) & 0xff;
    out[2] = (v >>> 16) & 0xff;
    out[3] = (v >>> 24) & 0xff;
    // Data2: 4 hex, uint16 little-endian
    v = parseInt(s.slice(9, 13), 16);
    out[4] = v & 0xff;
    out[5] = (v >>> 8) & 0xff;
    // Data3: 4 hex, uint16 little-endian
    v = parseInt(s.slice(14, 18), 16);
    out[6] = v & 0xff;
    out[7] = (v >>> 8) & 0xff;
    // Data4: 4 hex, as-is (string order)
    v = parseInt(s.slice(19, 23), 16);
    out[8] = (v >>> 8) & 0xff;
    out[9] = v & 0xff;
    // Data5: 12 hex, 6 bytes, as-is (string order)
    // Parse as two chunks to avoid any precision worries, keep it simple.
    v = parseInt(s.slice(24, 32), 16); // 8 hex -> 4 bytes
    out[10] = (v >>> 24) & 0xff;
    out[11] = (v >>> 16) & 0xff;
    out[12] = (v >>> 8) & 0xff;
    out[13] = v & 0xff;
    v = parseInt(s.slice(32, 36), 16); // 4 hex -> 2 bytes
    out[14] = (v >>> 8) & 0xff;
    out[15] = v & 0xff;
    // Ensure all parsed parts were valid hex (parseInt can yield NaN)
    for (let i = 0; i < 16; i++) {
        if (!Number.isFinite(out[i])) {
            throw new Error(`Invalid GUID format: ${guid}`);
        }
    }
    // Also catch NaN early (more useful error locality)
    // If any parseInt produced NaN, assignments above would have become 0,
    // so instead validate hex characters directly with a lightweight check.
    // (Keeps code small while staying strict.)
    if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(s)) {
        throw new Error(`Invalid GUID format: ${guid}`);
    }
    return out;
}
export class Guid {
    constructor(bytes) {
        if (bytes.length !== 16)
            throw new Error("GUID must be exactly 16 bytes");
        this.bytes = bytes;
    }
    static fromString(guid) {
        return new Guid(parseWindowsGuid(guid));
    }
    /**
     * Convert Windows / CFBF byte order into canonical GUID string:
     * xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
     */
    toString() {
        const b = this.bytes;
        const hx = (n) => n.toString(16).padStart(2, "0");
        // Data1 (uint32 LE) -> big-endian text
        const g1 = hx(b[3]) + hx(b[2]) + hx(b[1]) + hx(b[0]);
        // Data2 (uint16 LE)
        const g2 = hx(b[5]) + hx(b[4]);
        // Data3 (uint16 LE)
        const g3 = hx(b[7]) + hx(b[6]);
        // Data4 (as-is)
        const g4 = hx(b[8]) + hx(b[9]);
        // Data5 (as-is)
        const g5 = hx(b[10]) +
            hx(b[11]) +
            hx(b[12]) +
            hx(b[13]) +
            hx(b[14]) +
            hx(b[15]);
        return `${g1}-${g2}-${g3}-${g4}-${g5}`.toUpperCase();
    }
    /**
     * Compare against a Uint8Array containing GUID bytes
     * in Windows / CFBF layout.
     */
    equals(buf, offset = 0) {
        if (offset < 0 || buf.length - offset < 16)
            return false;
        const a = this.bytes;
        for (let i = 0; i < 16; i++) {
            if (buf[offset + i] !== a[i])
                return false;
        }
        return true;
    }
}
