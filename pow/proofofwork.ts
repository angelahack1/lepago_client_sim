import * as nodeCrypto from 'crypto';

export class ProofOfWork {
    private block: any;
    private difficulty: number;
    private target: string;

    /**
     * @param {Object} block - The block data to mine
     * @param {number} difficulty - Number of leading zeros required
     */
    constructor(block: any, difficulty: number = 4) {
        this.block = block;
        this.difficulty = difficulty;
        this.target = '0'.repeat(this.difficulty);
    }

    /**
     * Mines the block by finding a nonce that satisfies the difficulty
     * @returns {Object} The mined block with nonce and hash
     */
    mine(): { blockData: any, nonce: number, hash: string } {
        let nonce = 0;
        let hash: string;
        
        console.log(`Mining block with difficulty ${this.difficulty}...`);
        
        while (true) {
            hash = this.calculateHash(nonce);
            if (hash.startsWith(this.target)) {
                console.log(`Block mined! Nonce: ${nonce}`);
                console.log(`Hash: ${hash}`);
                break;
            }
            nonce++;
        }
        
        return {
            blockData: this.block,
            nonce: nonce,
            hash: hash
        };
    }

    /**
     * Calculates the SHA-256 hash of the block with the given nonce
     * @param {number} nonce - The nonce to use in the hash calculation
     * @returns {string} The resulting hash
     */
    calculateHash(nonce: number): string {
        const data = JSON.stringify({
            ...this.block,
            nonce: nonce
        });
        return nodeCrypto.createHash('sha256').update(data).digest('hex');
    }

    /**
     * Validates that a block's hash meets the difficulty target
     * @param {Object} block - The block to validate (assuming it has nonce and hash properties)
     * @returns {boolean} True if valid, false otherwise
     */
    validate(block: { nonce: number, hash: string, [key: string]: any }): boolean {
        const hashToVerify = this.calculateHash(block.nonce);
        return hashToVerify.startsWith(this.target) && hashToVerify === block.hash;
    }
}
