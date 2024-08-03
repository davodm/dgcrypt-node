const Dgcrypt = require('../dist/cjs/index');

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
        const encryptedData = dgcrypt.encrypt(data, secretKey);
        const decryptedData = dgcrypt.decrypt(encryptedData, secretKey);
        expect(decryptedData).toBe(data);
    });

    test('should encrypt and decrypt data successfully with aes-256-gcm', () => {
        dgcrypt.setCipherMethod('aes-256-gcm');
        const encryptedData = dgcrypt.encrypt(data, secretKey);
        const decryptedData = dgcrypt.decrypt(encryptedData, secretKey);
        expect(decryptedData).toBe(data);
    });

    test('should encrypt and decrypt data successfully with chacha20-poly1305', () => {
        dgcrypt.setCipherMethod('chacha20-poly1305');
        const encryptedData = dgcrypt.encrypt(data, secretKey);
        const decryptedData = dgcrypt.decrypt(encryptedData, secretKey);
        expect(decryptedData).toBe(data);
    });

    test('should throw error if key is not 32 characters', () => {
        expect(() => dgcrypt.setKey('shortkey')).toThrow('Secret key should be 32 characters');
    });

    test('should throw error if IV is not correct length for aes-256-cbc', () => {
        dgcrypt.setCipherMethod('aes-256-cbc');
        expect(() => dgcrypt.setIV('shortiv')).toThrow('IV should be 16 bytes');
    });

    test('should throw error if IV is not correct length for aes-256-gcm', () => {
        dgcrypt.setCipherMethod('aes-256-gcm');
        expect(() => dgcrypt.setIV('shortiv')).toThrow('IV should be 12 bytes');
    });

    test('should throw error if IV is not correct length for chacha20-poly1305', () => {
        dgcrypt.setCipherMethod('chacha20-poly1305');
        expect(() => dgcrypt.setIV('shortiv')).toThrow('IV should be 12 bytes');
    });

    test('should generate a random IV if not provided', () => {
        dgcrypt.setCipherMethod('aes-256-cbc');
        dgcrypt.setIV();
        const encryptedData = dgcrypt.encrypt(data, secretKey);
        const decryptedData = dgcrypt.decrypt(encryptedData, secretKey);
        expect(decryptedData).toBe(data);
    });

    test('should encrypt and decrypt data with a provided IV', () => {
        dgcrypt.setCipherMethod('aes-256-cbc');
        const iv = '1234567890123456'; // 16 bytes
        dgcrypt.setIV(iv);
        const encryptedData = dgcrypt.encrypt(data, secretKey);
        const decryptedData = dgcrypt.decrypt(encryptedData, secretKey);
        expect(decryptedData).toBe(data);
    });

    test('should reset IV after encryption if specified', () => {
        dgcrypt.setCipherMethod('aes-256-cbc');
        dgcrypt.setIV();
        const initialIV = dgcrypt.iv.toString('base64');
        dgcrypt.encrypt(data, secretKey, true);
        const resetIV = dgcrypt.iv;
        expect(resetIV).toBeNull();
    });

    test('should encrypt and decrypt large data successfully', () => {
        const largeData = 'a'.repeat(10 * 1024 * 1024); // 10 MB of data
        dgcrypt.setCipherMethod('aes-256-cbc');
        const encryptedData = dgcrypt.encrypt(largeData, secretKey);
        const decryptedData = dgcrypt.decrypt(encryptedData, secretKey);
        expect(decryptedData).toBe(largeData);
    });

    test('should throw error if decrypting with wrong key', () => {
        dgcrypt.setCipherMethod('aes-256-cbc');
        const encryptedData = dgcrypt.encrypt(data, secretKey);
        const wrongKey = 'wrongkeywrongkeywrongkeywrongke'; // 32 characters
        expect(() => dgcrypt.decrypt(encryptedData, wrongKey)).toThrow();
    });

    test('should throw error if decrypting tampered data', () => {
        dgcrypt.setCipherMethod('aes-256-cbc');
        const encryptedData = dgcrypt.encrypt(data, secretKey);
        const tamperedData = encryptedData.slice(0, -1) + 'A';
        expect(() => dgcrypt.decrypt(tamperedData, secretKey)).toThrow();
    });

    test('should generate a secure random key of correct length', () => {
        const generatedKey = dgcrypt.generateKey();
        expect(generatedKey).toBeInstanceOf(Buffer);
        expect(generatedKey.length).toBe(32);
    });
});
