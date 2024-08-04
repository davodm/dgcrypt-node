const crypto = require("crypto");

class Dgcrypt {
  constructor(cipherMethod = "aes-256-cbc") {
    this.supportedMethods = ["aes-256-cbc", "aes-256-gcm", "chacha20-poly1305"];
    this.setCipherMethod(cipherMethod);
    this.iv = null;
    this.key = null;
  }

  /**
   * Sets the cipher method.
   * @param {string} method The cipher method (e.g., aes-256-cbc, aes-256-gcm, chacha20-poly1305)
   * @return {Dgcrypt} The Dgcrypt instance
   */
  setCipherMethod(method) {
    if (!this.supportedMethods.includes(method)) {
      throw new Error("Cipher method not supported");
    }
    this.cipherMethod = method;
    return this;
  }

  /**
   * Sets the secret key for encryption and decryption.
   * The key is hashed using SHA-256 and truncated to 32 bytes.
   *
   * @param {string} key The secret key
   * @return {Dgcrypt} The Dgcrypt instance
   */
  setKey(key) {
    this.key = crypto
      .createHash("sha256")
      .update(key)
      .digest("hex")
      .slice(0, 32);
    return this;
  }

  /**
   * Auto-generates a secure random key in hex format (32 bytes).
   * @return {String} The generated key
   */
  generateKey() {
    this.setKey(crypto.randomBytes(32).toString("hex"));
    return this.key.toString("hex");
  }

  /**
   * Sets the initialization vector (IV) for encryption.
   * If no IV is provided, a secure random IV is generated.
   * @param {string|null} iv The IV (must be 16 bytes for AES-CBC, 12 bytes for AES-GCM and ChaCha20)
   * @return {Dgcrypt} The Dgcrypt instance
   */
  setIV(iv = null) {
    // Determine the IV length based on the cipher method
    const ivLength = crypto.getCipherInfo(this.cipherMethod).ivLength;

    if (!iv) {
      this.iv = crypto.randomBytes(ivLength);
    } else {
      if (Buffer.from(iv, "utf8").length !== ivLength) {
        throw new Error(
          `IV length should be ${ivLength} bytes for ${this.cipherMethod}`
        );
      }
      this.iv = Buffer.from(iv, "utf8");
    }
    return this;
  }

  /**
   * Encrypts a given string using the specified method.
   * @param {string} string The input string to encrypt
   * @param {string|null} secretKey The secret key for encryption
   * @param {boolean} resetIV Whether to reset the IV after encryption
   * @return {string} The encrypted string, base64 encoded
   */
  encrypt(string, secretKey = null, resetIV = true) {
    if (secretKey) {
      this.setKey(secretKey);
    } else if (!this.key) {
      throw new Error("Secret key is not defined");
    }

    if (!this.iv) {
      this.setIV();
    }

    let cipher,
      encrypted,
      tag = null;

    // Encrypt the string using the specified method
    switch (this.cipherMethod) {
      case "aes-256-cbc":
        cipher = crypto.createCipheriv(this.cipherMethod, this.key, this.iv);
        encrypted = Buffer.concat([cipher.update(string), cipher.final()]);
        break;
      case "aes-256-gcm":
      case "chacha20-poly1305":
        cipher = crypto.createCipheriv(this.cipherMethod, this.key, this.iv);
        encrypted = Buffer.concat([cipher.update(string), cipher.final()]);
        tag = cipher.getAuthTag();
        break;
      default:
        throw new Error("Unsupported cipher method");
    }

    let encryptedString = Buffer.from(encrypted).toString("hex");
    // Base64 encode the encrypted string
    encryptedString = Buffer.from(encryptedString).toString("base64");

    // Prepend the IV and tag (if any) to the encrypted string
    let result =
      this.iv.toString("hex") +
      (tag ? tag.toString("hex") : "") +
      encryptedString;
    // Base64 encode the result
    result = Buffer.from(result).toString("base64");

    if (resetIV) {
      this.iv = null;
    }

    return result;
  }

  /**
   * Decrypts a given string using the specified method.
   * @param {string} string The encrypted string to decrypt (base64 encoded)
   * @param {string|null} secretKey The secret key for decryption
   * @return {string} The decrypted string
   */
  decrypt(string, secretKey = null) {
    if (secretKey) {
      this.setKey(secretKey);
    } else if (!this.key) {
      throw new Error("Secret key is not defined");
    }

    // Decode the base64 encoded string
    let decodedString = Buffer.from(string, "base64").toString("utf8");

    // determine the IV length and tag length based on the cipher method
    const ivLength = crypto.getCipherInfo(this.cipherMethod).ivLength;
    const tagLength =
      this.cipherMethod === "aes-256-gcm" ||
      this.cipherMethod === "chacha20-poly1305"
        ? 16
        : 0;
    // Extract the IV and tag (if any) from the decoded string
    const iv = Buffer.from(decodedString.slice(0, ivLength * 2), "hex");
    const tag =
      tagLength > 0
        ? Buffer.from(
            decodedString.slice(ivLength * 2, (ivLength + tagLength) * 2),
            "hex"
          )
        : null;

    let encryptedData = decodedString.slice((ivLength + tagLength) * 2);
    // Decode the base64 encoded encrypted data
    encryptedData = Buffer.from(
      Buffer.from(encryptedData, "base64").toString("utf8"),
      "hex"
    );

    let decipher, decrypted;
    // Decrypt the string using the specified method
    try {
      switch (this.cipherMethod) {
        case "aes-256-cbc":
          decipher = crypto.createDecipheriv(this.cipherMethod, this.key, iv);
          decrypted = Buffer.concat([
            decipher.update(encryptedData),
            decipher.final(),
          ]);
          break;
        case "aes-256-gcm":
        case "chacha20-poly1305":
          decipher = crypto.createDecipheriv(this.cipherMethod, this.key, iv);
          decipher.setAuthTag(tag);
          decrypted = Buffer.concat([
            decipher.update(encryptedData),
            decipher.final(),
          ]);
          break;
        default:
          throw new Error("Unsupported cipher method");
      }
    } catch (e) {
      throw new Error("Decryption failed. Data may have been tampered with.");
    }

    return decrypted.toString("utf8");
  }
}

module.exports = Dgcrypt;
