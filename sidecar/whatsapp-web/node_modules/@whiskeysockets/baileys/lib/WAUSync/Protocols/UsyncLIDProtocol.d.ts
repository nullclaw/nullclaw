import type { USyncQueryProtocol } from '../../Types/USync.js';
import type { BinaryNode } from '../../WABinary/index.js';
export declare class USyncLIDProtocol implements USyncQueryProtocol {
    name: string;
    getQueryElement(): BinaryNode;
    getUserElement(): null;
    parser(node: BinaryNode): string | null;
}
//# sourceMappingURL=UsyncLIDProtocol.d.ts.map