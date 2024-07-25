const Dgcrypt = require('../dist/cjs/index');

describe('Dgcrypt', () => {
    let dgcrypt;
    const secretKey = '12345678901234567890123456789012'; // 32 characters
    const data = 'Hello, World!';

    beforeEach(() => {
        dgcrypt = new Dgcrypt();
        dgcrypt.setKey(secretKey);
    });

    test('should encrypt and decrypt data successfully', () => {
        const encryptedData = dgcrypt.encrypt(data, secretKey);
        const decryptedData = dgcrypt.decrypt(encryptedData, secretKey);
        expect(decryptedData).toBe(data);
    });

    test('should throw error if key is not 32 characters', () => {
        expect(() => dgcrypt.setKey('shortkey')).toThrow('Secret key should be 32 characters');
    });

    test('should throw error if IV is not 16 bytes', () => {
        expect(() => dgcrypt.setIV('shortiv')).toThrow('IV should be 16 bytes');
    });

    test('should generate a random IV if not provided', () => {
        dgcrypt.setIV();
        const encryptedData = dgcrypt.encrypt(data, secretKey);
        const decryptedData = dgcrypt.decrypt(encryptedData, secretKey);
        expect(decryptedData).toBe(data);
    });
});
