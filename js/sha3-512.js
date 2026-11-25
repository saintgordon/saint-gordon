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

  function bytesToHex(bytes) {
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
  }

  function hexToBytes(hex) {
    const clean = String(hex || "").trim();
    if (!clean || clean.length % 2 !== 0) {
      throw new Error("Invalid hex input.");
    }
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
      const v = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
      if (Number.isNaN(v)) throw new Error("Invalid hex byte.");
      out[i] = v;
    }
    return out;
  }

  function concatBytes() {
    let total = 0;
    for (let i = 0; i < arguments.length; i++) total += arguments[i].length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (let i = 0; i < arguments.length; i++) {
      out.set(arguments[i], offset);
      offset += arguments[i].length;
    }
    return out;
  }

  /**
   * Compute HMAC-SHA256 hex digest using native Web Crypto (SubtleCrypto).
   */
  async function hmacSha256Hex(keyInput, msgInput) {
    const subtle = typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle;
    if (!subtle) {
      throw new Error("Secure Web Crypto (HTTPS) is required for encrypted sign-in.");
    }
    const keyBytes = keyInput instanceof Uint8Array ? keyInput : utf8ToBytes(keyInput);
    const msgBytes = msgInput instanceof Uint8Array ? msgInput : utf8ToBytes(msgInput);
    const cryptoKey = await subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sigBuf = await subtle.sign("HMAC", cryptoKey, msgBytes);
    return bytesToHex(new Uint8Array(sigBuf));
  }

  /**
   * Seal login password inside an ephemeral NIST P-256 ECDH + Encrypt-then-MAC
   * fixed-256-byte envelope bound to the server's one-time challenge (nonce + exp).
   * Neither plaintext password, password length, nor static SHA3-512 hash is sent over the wire.
   */
  async function sealLoginEnvelope(password, nonce, exp, serverPubHex) {
    const gCrypto = typeof globalThis !== "undefined" && globalThis.crypto;
    const subtle = gCrypto && gCrypto.subtle;
    if (!subtle || typeof gCrypto.getRandomValues !== "function") {
      throw new Error("Secure Web Crypto (HTTPS) is required for encrypted sign-in.");
    }

    const BLOCK_BYTES = 256;
    const serverPubBytes = hexToBytes(serverPubHex);
    const serverPubKey = await subtle.importKey(
      "raw",
      serverPubBytes,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );

    // Fresh ephemeral client P-256 keypair (forward secrecy per attempt)
    const ephPair = await subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
    const epkBytes = new Uint8Array(await subtle.exportKey("raw", ephPair.publicKey));
    const sharedBuf = await subtle.deriveBits(
      { name: "ECDH", public: serverPubKey },
      ephPair.privateKey,
      256
    );
    const shared = new Uint8Array(sharedBuf);

    // Fixed-length 256-byte randomly padded payload (hides password length too)
    const msgBytes = utf8ToBytes(JSON.stringify({ n: String(nonce), e: Number(exp), p: String(password) }));
    if (msgBytes.length > BLOCK_BYTES - 2) {
      throw new Error("Password is too long.");
    }
    const block = new Uint8Array(BLOCK_BYTES);
    gCrypto.getRandomValues(block);
    block[0] = (msgBytes.length >> 8) & 0xff;
    block[1] = msgBytes.length & 0xff;
    block.set(msgBytes, 2);

    const nonceBytes = utf8ToBytes(String(nonce));
    const encKey = new Uint8Array(
      await subtle.digest("SHA-256", concatBytes(utf8ToBytes("sg-enc-v1:"), shared, nonceBytes, epkBytes))
    );
    const macKey = new Uint8Array(
      await subtle.digest("SHA-256", concatBytes(utf8ToBytes("sg-mac-v1:"), shared, nonceBytes, epkBytes))
    );

    // 8-block SHA-256-CTR stream encryption
    const ct = new Uint8Array(BLOCK_BYTES);
    const ctrBuf = new Uint8Array(4);
    for (let ctr = 0; ctr < BLOCK_BYTES / 32; ctr++) {
      ctrBuf[0] = (ctr >>> 24) & 0xff;
      ctrBuf[1] = (ctr >>> 16) & 0xff;
      ctrBuf[2] = (ctr >>> 8) & 0xff;
      ctrBuf[3] = ctr & 0xff;
      const ks = new Uint8Array(await subtle.digest("SHA-256", concatBytes(encKey, ctrBuf)));
      const base = ctr * 32;
      for (let j = 0; j < 32; j++) {
        ct[base + j] = block[base + j] ^ ks[j];
      }
    }

    // Encrypt-then-MAC integrity tag binding nonce, expiry, ephemeral pubkey, and ciphertext
    const macData = concatBytes(utf8ToBytes(String(nonce) + ":" + String(Number(exp)) + ":"), epkBytes, ct);
    const tag = await hmacSha256Hex(macKey, macData);

    // Zero sensitive buffers
    block.fill(0);
    shared.fill(0);
    encKey.fill(0);
    macKey.fill(0);

    return {
      epk: bytesToHex(epkBytes),
      ct: bytesToHex(ct),
      tag: tag,
    };
  }

  /**
   * Build one-time HMAC proof helper (retained for crypto verification tests).
   */
  async function createLoginProof(password, nonce, exp) {
    const pwdHash = sha3_512(password);
    return hmacSha256Hex(pwdHash, String(nonce) + ":" + String(exp));
  }

  return {
    sha3_512: sha3_512,
    hmacSha256Hex: hmacSha256Hex,
    sealLoginEnvelope: sealLoginEnvelope,
    createLoginProof: createLoginProof,
  };
});
