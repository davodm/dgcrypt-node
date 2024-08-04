const Dgcrypt = require('../src/index');

describe('Dgcrypt', () => {
    let dgcrypt;
    const secretKey = '12345678901234567890123456789012'; // 32 characters
    const data = 'Hello, World!';

    beforeEach(() => {
        dgcrypt = new Dgcrypt();
        dgcrypt.setKey(secretKey);
    });

    test('should encrypt and decrypt data successfully with aes-256-cbc', () => {
        dgcrypt.setCipherMethod('aes-256-cbc');
        const encryptedData = dgcrypt.encrypt(data);
        const decryptedData = dgcrypt.decrypt(encryptedData);
        expect(decryptedData).toBe(data);
    });

    test('should encrypt and decrypt data successfully with aes-256-gcm', () => {
        dgcrypt.setCipherMethod('aes-256-gcm');
        const encryptedData = dgcrypt.encrypt(data);
        const decryptedData = dgcrypt.decrypt(encryptedData);
        expect(decryptedData).toBe(data);
    });

    test('should encrypt and decrypt data successfully with chacha20-poly1305', () => {
        dgcrypt.setCipherMethod('chacha20-poly1305');
        const encryptedData = dgcrypt.encrypt(data);
        const decryptedData = dgcrypt.decrypt(encryptedData);
        expect(decryptedData).toBe(data);
    });

    test('should throw error if IV is not correct length for aes-256-cbc', () => {
        dgcrypt.setCipherMethod('aes-256-cbc');
        expect(() => dgcrypt.setIV('shortiv')).toThrow('IV length should be 16 bytes for aes-256-cbc');
    });

    test('should throw error if IV is not correct length for aes-256-gcm', () => {
        dgcrypt.setCipherMethod('aes-256-gcm');
        expect(() => dgcrypt.setIV('shortiv')).toThrow('IV length should be 12 bytes for aes-256-gcm');
    });

    test('should throw error if IV is not correct length for chacha20-poly1305', () => {
        dgcrypt.setCipherMethod('chacha20-poly1305');
        expect(() => dgcrypt.setIV('shortiv')).toThrow('IV length should be 12 bytes for chacha20-poly1305');
    });

    test('should generate a random IV if not provided', () => {
        dgcrypt.setCipherMethod('aes-256-cbc');
        dgcrypt.setIV();
        const encryptedData = dgcrypt.encrypt(data);
        const decryptedData = dgcrypt.decrypt(encryptedData);
        expect(decryptedData).toBe(data);
    });

    test('should encrypt and decrypt data with a provided IV', () => {
        dgcrypt.setCipherMethod('aes-256-cbc');
        const iv = '1234567890123456'; // 16 bytes
        dgcrypt.setIV(iv);
        const encryptedData = dgcrypt.encrypt(data);
        const decryptedData = dgcrypt.decrypt(encryptedData);
        expect(decryptedData).toBe(data);
    });

    test('should reset IV after encryption if specified', () => {
        dgcrypt.setCipherMethod('aes-256-cbc');
        dgcrypt.setIV();
        const initialIV = dgcrypt.iv.toString('base64');
        dgcrypt.encrypt(data, secretKey, true);
        expect(dgcrypt.iv).toBeNull();
    });

    test('should encrypt and decrypt large data successfully', () => {
        const largeData = 'a'.repeat(10 * 1024 * 1024); // 10 MB of data
        dgcrypt.setCipherMethod('aes-256-cbc');
        const encryptedData = dgcrypt.encrypt(largeData);
        const decryptedData = dgcrypt.decrypt(encryptedData);
        expect(decryptedData).toBe(largeData);
    });

    test('should throw error if decrypting with wrong key', () => {
        dgcrypt.setCipherMethod('aes-256-cbc');
        const encryptedData = dgcrypt.encrypt(data);
        const wrongKey = 'wrongkeywrongkeywrongkeywrongke'; // 32 characters
        const wrongDgcrypt = new Dgcrypt('aes-256-cbc');
        wrongDgcrypt.setKey(wrongKey);
        expect(() => wrongDgcrypt.decrypt(encryptedData)).toThrow();
    });

    test('should throw error if decrypting tampered data', () => {
        dgcrypt.setCipherMethod('aes-256-cbc');
        const encryptedData = dgcrypt.encrypt(data);
        const tamperedData = encryptedData.slice(0, -10) + 'z0000';
        expect(() => dgcrypt.decrypt(tamperedData)).toThrow("Decryption failed. Data may have been tampered with.");
    
    });

    test('should generate a secure random key of correct length', () => {
        const generatedKey = dgcrypt.generateKey();
        expect(typeof generatedKey).toBe('string');
        expect(generatedKey.length).toBe(32);
    });

    test('should throw error if cipher method is not supported', () => {
        expect(() => dgcrypt.setCipherMethod('unsupported-method')).toThrow('Cipher method not supported');
    });

    test('should encrypt and decrypt data with all supported methods', () => {
        const methods = ['aes-256-cbc', 'aes-256-gcm', 'chacha20-poly1305'];
        methods.forEach(method => {
            dgcrypt.setCipherMethod(method);
            const encryptedData = dgcrypt.encrypt(data);
            const decryptedData = dgcrypt.decrypt(encryptedData);
            expect(decryptedData).toBe(data);
        });
    });

    test('should handle empty string encryption and decryption', () => {
        const emptyString = '';
        const encryptedData = dgcrypt.encrypt(emptyString);
        const decryptedData = dgcrypt.decrypt(encryptedData);
        expect(decryptedData).toBe(emptyString);
    });

    test('should handle special characters in data', () => {
        const specialChars = '!@#$%^&*()_+{}[]|:;"\'<>,.?/~`';
        const encryptedData = dgcrypt.encrypt(specialChars);
        const decryptedData = dgcrypt.decrypt(encryptedData);
        expect(decryptedData).toBe(specialChars);
    });

    test('should handle Unicode characters', () => {
        const unicodeString = '你好，世界！😊';
        const encryptedData = dgcrypt.encrypt(unicodeString);
        const decryptedData = dgcrypt.decrypt(encryptedData);
        expect(decryptedData).toBe(unicodeString);
    });

    test('should throw error if key is not provided for encryption', () => {
        dgcrypt.key = null;
        expect(() => dgcrypt.encrypt(data)).toThrow('Secret key is not defined');
    });

    test('should throw error if key is not provided for decryption', () => {
        const encryptedData = dgcrypt.encrypt(data);
        dgcrypt.key = null;
        expect(() => dgcrypt.decrypt(encryptedData)).toThrow('Secret key is not defined');
    });

    test('should throw error if encrypted data is corrupted', () => {
        const encryptedData = dgcrypt.encrypt(data);
        const corruptedData = encryptedData.substring(0, encryptedData.length - 5);
        expect(() => dgcrypt.decrypt(corruptedData)).toThrow();
    });

    test('should correctly handle different key lengths', () => {
        const shortKey = 'shortkey';
        const longKey = 'a'.repeat(100);
        dgcrypt.setKey(shortKey);
        expect(dgcrypt.key.length).toBe(32);
        dgcrypt.setKey(longKey);
        expect(dgcrypt.key.length).toBe(32);
    });
});
