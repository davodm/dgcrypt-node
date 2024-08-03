const crypto = require("crypto");

class Dgcrypt {
  constructor(cipherMethod = "aes-256-cbc") {
    this.setCipherMethod(cipherMethod);
    this.iv = null;
    this.key = null;
  }

  /**
   * Sets the cipher method.
   * @param {string} method The cipher method (e.g., aes-256-cbc, aes-256-gcm, chacha20-poly1305)
   */
  setCipherMethod(method) {
    const supportedMethods = ["aes-256-cbc", "aes-256-gcm", "chacha20-poly1305"];
    if (!supportedMethods.includes(method)) {
      throw new Error(`Unsupported method. Supported methods: ${supportedMethods.join(", ")}`);
    }
    this.cipherMethod = method;
  }

  /**
   * Sets the secret key for encryption and decryption.
   * @param {string} key The secret key (must be 32 characters)
   */
  setKey(key) {
    if (key.length !== 32) {
      throw new Error("Secret key should be 32 characters");
    }
    this.key = Buffer.from(key, 'utf8');
  }

  /**
   * Auto-generates a secure random key.
   * @return {Buffer} The generated key
   */
  generateKey() {
    this.key = crypto.randomBytes(32);
    return this.key;
  }

  /**
   * Sets the initialization vector (IV) for encryption.
   * If no IV is provided, a secure random IV is generated.
   * @param {string|null} iv The IV (must be 16 bytes for AES-CBC, 12 bytes for AES-GCM and ChaCha20)
   */
  setIV(iv = null) {
    let ivLength;
    if (this.cipherMethod.includes("gcm") || this.cipherMethod.includes("chacha20")) {
      ivLength = 12; // GCM and ChaCha20-Poly1305 use 12 bytes IV
    } else {
      ivLength = 16; // CBC uses 16 bytes IV
    }

    if (!iv) {
      this.iv = crypto.randomBytes(ivLength);
    } else {
      if (iv.length !== ivLength) {
        throw new Error(`IV should be ${ivLength} bytes`);
      }
      this.iv = Buffer.from(iv, 'utf8');
    }
  }

  /**
   * Encrypts a given string using the specified method.
   * @param {string} data The input string to encrypt
   * @param {string|null} secretKey The secret key for encryption
   * @param {boolean} resetIV Whether to reset the IV after encryption
   * @return {string} The encrypted string, base64 encoded
   */
  encrypt(data, secretKey = null, resetIV = false) {
    if (secretKey) {
      this.setKey(secretKey);
    } else if (!this.key) {
      throw new Error("Secret key is not defined");
    }

    if (!this.iv) {
      this.setIV();
    }

    const cipher = crypto.createCipheriv(this.cipherMethod, this.key, this.iv);
    let encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    let authTag = Buffer.alloc(0);

    if (this.cipherMethod.includes('gcm') || this.cipherMethod.includes('chacha20')) {
      authTag = cipher.getAuthTag();
    }

    const combined = Buffer.concat([this.iv, authTag, encrypted]);
    const result = combined.toString('base64');

    if (resetIV) {
      this.iv = null;
    }

    return result;
  }

  /**
   * Decrypts a given string using the specified method.
   * @param {string} encrypted The encrypted string to decrypt (base64 encoded)
   * @param {string|null} secretKey The secret key for decryption
   * @return {string} The decrypted string
   */
  decrypt(encrypted, secretKey = null) {
    if (secretKey) {
      this.setKey(secretKey);
    } else if (!this.key) {
      throw new Error("Secret key is not defined");
    }

    const decoded = Buffer.from(encrypted, 'base64');
    const ivLength = this.cipherMethod.includes("gcm") || this.cipherMethod.includes("chacha20") ? 12 : 16;
    const authTagLength = this.cipherMethod.includes("gcm") || this.cipherMethod.includes("chacha20") ? 16 : 0;
    const iv = decoded.subarray(0, ivLength);
    const authTag = authTagLength ? decoded.subarray(ivLength, ivLength + authTagLength) : null;
    const encryptedText = decoded.subarray(ivLength + authTagLength);

    const decipher = crypto.createDecipheriv(this.cipherMethod, this.key, iv);
    if (authTag) {
      decipher.setAuthTag(authTag);
    }

    let decrypted = decipher.update(encryptedText, null, 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}

module.exports = Dgcrypt;
