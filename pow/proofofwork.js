"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.ProofOfWork = void 0;
const nodeCrypto = __importStar(require("crypto"));
class ProofOfWork {
    /**
     * @param {Object} block - The block data to mine
     * @param {number} difficulty - Number of leading zeros required
     */
    constructor(block, difficulty = 4) {
        this.block = block;
        this.difficulty = difficulty;
        this.target = '0'.repeat(this.difficulty);
    }
    /**
     * Mines the block by finding a nonce that satisfies the difficulty
     * @returns {Object} The mined block with nonce and hash
     */
    mine() {
        let nonce = 0;
        let hash;
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
    calculateHash(nonce) {
        const data = JSON.stringify(Object.assign(Object.assign({}, this.block), { nonce: nonce }));
        return nodeCrypto.createHash('sha256').update(data).digest('hex');
    }
    /**
     * Validates that a block's hash meets the difficulty target
     * @param {Object} block - The block to validate (assuming it has nonce and hash properties)
     * @returns {boolean} True if valid, false otherwise
     */
    validate(block) {
        const hashToVerify = this.calculateHash(block.nonce);
        return hashToVerify.startsWith(this.target) && hashToVerify === block.hash;
    }
}
exports.ProofOfWork = ProofOfWork;
