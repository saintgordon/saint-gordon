/* Saint Gordon Collective — NIST FIPS 202 SHA3-512 & HMAC-SHA256 (Zero Dependencies)
 * Used by /admin so plaintext passwords NEVER leave the browser.
 * Runs identically in Safari 14+, Firefox, Chrome, Edge, and Node.js.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.SaintCrypto = factory();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const MASK64 = 0xffffffffffffffffn;

  const RC = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
  ];

  // Rotation offsets r[x + 5*y]
  const ROT = [
     0n,  1n, 62n, 28n, 27n,
    36n, 44n,  6n, 55n, 20n,
     3n, 10n, 43n, 25n, 39n,
    41n, 45n, 15n, 21n,  8n,
    18n,  2n, 61n, 56n, 14n,
  ];

  function rotl64(x, n) {
    if (n === 0n) return x;
    return ((x << n) | (x >> (64n - n))) & MASK64;
  }

  function keccakF1600(state) {
    const C = new Array(5);
    const D = new Array(5);
    const B = new Array(25);

    for (let round = 0; round < 24; round++) {
      // Theta
      for (let x = 0; x < 5; x++) {
        C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
      }
      for (let x = 0; x < 5; x++) {
        D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1n);
      }
      for (let x = 0; x < 5; x++) {
        for (let y = 0; y < 25; y += 5) {
          state[x + y] = (state[x + y] ^ D[x]) & MASK64;
        }
      }

      // Rho & Pi
      for (let x = 0; x < 5; x++) {
        for (let y = 0; y < 5; y++) {
          const idx = x + 5 * y;
          const nx = y;
          const ny = (2 * x + 3 * y) % 5;
          B[nx + 5 * ny] = rotl64(state[idx], ROT[idx]);
        }
      }

      // Chi
      for (let y = 0; y < 25; y += 5) {
        for (let x = 0; x < 5; x++) {
          state[x + y] = (B[x + y] ^ ((~B[((x + 1) % 5) + y] & MASK64) & B[((x + 2) % 5) + y])) & MASK64;
        }
      }

      // Iota
      state[0] = (state[0] ^ RC[round]) & MASK64;
    }
  }

  function utf8ToBytes(str) {
    if (typeof TextEncoder !== "undefined") {
      return new TextEncoder().encode(String(str));
    }
    const encoded = unescape(encodeURIComponent(String(str)));
    const out = new Uint8Array(encoded.length);
    for (let i = 0; i < encoded.length; i++) out[i] = encoded.charCodeAt(i);
    return out;
  }

  /**
   * Compute NIST FIPS 202 SHA3-512 hex digest (128 lowercase hex chars).
   * Rate = 72 bytes (576 bits), Capacity = 128 bytes (1024 bits), Domain suffix = 0x06.
   */
  function sha3_512(input) {
    const msg = input instanceof Uint8Array ? input : utf8ToBytes(input);
    const rate = 72;
    const state = new Array(25).fill(0n);

    // Pad with SHA-3 domain separator 0x06 ... 0x80
    const rem = msg.length % rate;
    const padLen = rate - rem;
    const padded = new Uint8Array(msg.length + padLen);
    padded.set(msg, 0);
    padded[msg.length] ^= 0x06;
    padded[padded.length - 1] ^= 0x80;

    // Absorb
    for (let offset = 0; offset < padded.length; offset += rate) {
      for (let lane = 0; lane < rate / 8; lane++) {
        let v = 0n;
        const base = offset + lane * 8;
        for (let b = 0; b < 8; b++) {
          v |= BigInt(padded[base + b]) << BigInt(b * 8);
        }
        state[lane] = (state[lane] ^ v) & MASK64;
      }
      keccakF1600(state);
    }

    // Squeeze 64 bytes (8 lanes of 64-bit LE)
    let hex = "";
    for (let lane = 0; lane < 8; lane++) {
      let v = state[lane];
      for (let b = 0; b < 8; b++) {
        const byteVal = Number((v >> BigInt(b * 8)) & 0xffn);
        hex += byteVal.toString(16).padStart(2, "0");
      }
    }
    return hex;
  }

  /**
   * Compute HMAC-SHA256 hex digest using native Web Crypto (SubtleCrypto).
   */
  async function hmacSha256Hex(keyStr, msgStr) {
    const subtle = typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle;
    if (!subtle) {
      throw new Error("Secure Web Crypto (HTTPS) is required for password-free challenge authentication.");
    }
    const keyBytes = utf8ToBytes(keyStr);
    const msgBytes = utf8ToBytes(msgStr);
    const cryptoKey = await subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sigBuf = await subtle.sign("HMAC", cryptoKey, msgBytes);
    const sigBytes = new Uint8Array(sigBuf);
    let hex = "";
    for (let i = 0; i < sigBytes.length; i++) {
      hex += sigBytes[i].toString(16).padStart(2, "0");
    }
    return hex;
  }

  /**
   * Build one-time zero-plaintext login proof bound to a server challenge (nonce + exp).
   * Neither the plaintext password nor the raw SHA3-512 hash is ever transmitted.
   */
  async function createLoginProof(password, nonce, exp) {
    const pwdHash = sha3_512(password);
    return hmacSha256Hex(pwdHash, String(nonce) + ":" + String(exp));
  }

  return {
    sha3_512: sha3_512,
    hmacSha256Hex: hmacSha256Hex,
    createLoginProof: createLoginProof,
  };
});
