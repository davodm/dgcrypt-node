# Dgcrypt

Dgcrypt is a simple Node.js library for encryption and decryption using various encryption methods, including AES-256-CBC, AES-256-GCM, and ChaCha20-Poly1305. It is designed to securely encrypt data on the backend, which can then be easily decrypted on the client side, such as on Android, iOS, and other platforms. This ensures that the data remains secure during transmission and cannot be easily cracked in between.

## Platform Compatibility
The Dgcrypt library is designed to work seamlessly across multiple platforms. You can find corresponding libraries for the following platforms:

- **Android**: [Dgcrypt-Android](https://github.com/davodm/dgcrypt-android)
- **PHP**: [Dgcrypt-PHP](https://github.com/davodm/dgcrypt-php)

These libraries allow you to easily decrypt data that was encrypted on the backend using this PHP library, ensuring secure communication between your backend and client applications.

## Supported Encryption Methods
Dgcrypt supports the following encryption methods:
- **AES-256-CBC**: Standard encryption method providing confidentiality.
- **AES-256-GCM**: Provides both encryption and authentication.
- **ChaCha20-Poly1305**: Modern encryption method known for its performance and security.

## Installation

You can install the package via npm, available for Node.js v16 and above:

```bash
npm install @davodm/dgcrypt-node
```

## Usage
#### Encrypting Data:

```javascript
const Dgcrypt = require('@davodm/dgcrypt-node');

const dgcrypt = new Dgcrypt('aes-256-cbc'); // Specify the encryption method
const secretKey = 'your-secret-key';
const data = 'Hello, World!';

const encryptedData = dgcrypt.encrypt(data, secretKey);
console.log('Encrypted Data:', encryptedData);
```

#### Decrypting Data:

```javascript
const Dgcrypt = require('@davodm/dgcrypt-node');

const dgcrypt = new Dgcrypt('aes-256-cbc'); // Specify the encryption method
const secretKey = 'your-secret-key';
const encryptedData = 'your-encrypted-data';

const decryptedData = dgcrypt.setCipherMethod('aes-256-cbc').decrypt(encryptedData, secretKey);
console.log('Decrypted Data:', decryptedData);
```

#### Generating a Secure Key
```javascript
const Dgcrypt = require('@davodm/dgcrypt-node');

const dgcrypt = new Dgcrypt();
const generatedKey = dgcrypt.generateKey();
console.log('Generated Key:', generatedKey); // Display the key in hexadecimal format
```

## Testing
To run the tests, use Jest:

```bash
npm test
```

## License
This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## Author
Davod Mozafari - [Twitter](https://twitter.com/davodmozafari)
