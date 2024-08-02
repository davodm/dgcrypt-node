# Dgcrypt

Dgcrypt is a simple Node.js library for encryption and decryption using AES-256-CBC. It is designed to securely encrypt data on the backend, which can then be easily decrypted on the client side, such as on Android, iOS, and other platforms. This ensures that the data remains secure during transmission and cannot be easily cracked in between.

## Platform Compatibility
The Dgcrypt library is designed to work seamlessly across multiple platforms. You can find corresponding libraries for the following platforms:

- **Android**: [Dgcrypt-Android](https://github.com/davodm/dgcrypt-android)
- **PHP**: [Dgcrypt-PHP](https://github.com/davodm/dgcrypt-php)

These libraries allow you to easily decrypt data that was encrypted on the backend using this PHP library, ensuring secure communication between your backend and client applications.

## Installation

You can install the package via npm, available for Node.js v16 and above:

```bash
npm install @davodm/dgcrypt-node
```

## Usage
#### Encrypting Data:

```javascript
const Dgcrypt = require('@davodm/dgcrypt-node');

const dgcrypt = new Dgcrypt();
const secretKey = 'your-32-character-long-key';
const data = 'Hello, World!';

const encryptedData = dgcrypt.encrypt(data, secretKey);
console.log('Encrypted Data:', encryptedData);
```

#### Decrypting Data:

```javascript
const Dgcrypt = require('@davodm/dgcrypt-node');

const dgcrypt = new Dgcrypt();
const secretKey = 'your-32-character-long-key';
const encryptedData = 'your-encrypted-data';

const decryptedData = dgcrypt.decrypt(encryptedData, secretKey);
console.log('Decrypted Data:', decryptedData);
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
