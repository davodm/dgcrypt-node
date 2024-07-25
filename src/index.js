const crypto = require('crypto');

class Dgcrypt {
    constructor() {
        this.algorithm = 'aes-256-cbc';
        this.key = null;
        this.iv = null;
    }

    /**
     * Sets the secret key for encryption and decryption.
     * @param {string} key The secret key (must be 32 characters)
     */
    setKey(key) {
        if (key.length !== 32) {
            throw new Error('Secret key should be 32 characters');
        }
        this.key = key;
    }

    /**
     * Sets the initialization vector (IV) for encryption.
     * If no IV is provided, a secure random IV is generated.
     * @param {string|null} iv The IV (must be 16 bytes)
     */
    setIV(iv = null) {
        if (!iv) {
            this.iv = crypto.randomBytes(16);
        } else {
            if (iv.length !== 16) {
                throw new Error('IV should be 16 bytes');
            }
            this.iv = Buffer.from(iv, 'utf8');
        }
    }

    /**
     * Encrypts a given string using AES-256-CBC.
     * @param {string} data The input string to encrypt
     * @param {string|null} secretKey Optional secret key for encryption
     * @param {boolean} resetIV Whether to reset the IV after encryption
     * @return {string} The encrypted string, base64 encoded
     */
    encrypt(data, secretKey = null, resetIV = false) {
        if (secretKey) {
            this.setKey(secretKey);
        } else if (!this.key) {
            throw new Error('Secret key is not defined');
        }

        if (!this.iv) {
            this.setIV();
        }

        const cipher = crypto.createCipheriv(this.algorithm, Buffer.from(this.key), this.iv);
        let encrypted = cipher.update(data, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        const ivBase64 = this.iv.toString('base64');
        const encryptedString = ivBase64 + encrypted;

        if (resetIV) {
            this.iv = null;
        }

        return encryptedString;
    }

    /**
     * Decrypts a given string using AES-256-CBC.
     * @param {string} encrypted The encrypted string to decrypt (base64 encoded)
     * @param {string|null} secretKey Optional secret key for decryption
     * @return {string} The decrypted string
     */
    decrypt(encrypted, secretKey = null) {
        if (secretKey) {
            this.setKey(secretKey);
        } else if (!this.key) {
            throw new Error('Key for decrypting is not defined');
        }

        const iv = Buffer.from(encrypted.slice(0, 24), 'base64');
        const encryptedText = encrypted.slice(24);

        const decipher = crypto.createDecipheriv(this.algorithm, Buffer.from(this.key), iv);
        let decrypted = decipher.update(encryptedText, 'base64', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    }
}

module.exports = Dgcrypt;
