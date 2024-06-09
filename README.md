## react-native-aes-256 Library

This React Native library provides a secure and convenient way to encrypt and decrypt data using the industry-standard AES-256 algorithm. It seamlessly integrates with your React Native application, allowing you to protect sensitive information on both Android and iOS platforms.

**Key Features:**

- **Robust AES-256 Encryption:** Leverages the highly secure AES-256 encryption algorithm for reliable data protection.
- **Native Module Integration:** Utilizes a native module for enhanced performance and platform-specific security features.
- **Simplified API:** Offers a user-friendly API with functions for encryption, decryption, and secure key/IV generation.
- **Error Handling:** Includes error checking for invalid key and IV lengths, preventing potential issues.

**Installation**

1. **Dependency Installation:** Install the library using npm or Yarn:

   ```bash
   npm install react-native-aes-256
   ```

   ```bash
   yarn add react-native-aes-256
   ```
2. **Platform-Specific Linking:**

   - **iOS:** Run `pod install` in your iOS project directory.
   - **Android:** Rebuild your app after installing the package.

**Usage**

1. **Import the functions:**

   ```javascript
   import { encrypt, decrypt, generateSecureKey, generateSecureIV } from 'react-native-aes-256';
   ```
2. **Encryption:**

   ```javascript
   // Optional you can use any 32 character string
   const secureKey = await generateSecureKey('your_password'); 

   // Optional you can use any 16 character string
   const iv = await generateSecureIV('another_password'); 

   const encryptedData = await encrypt(secureKey, iv, 'your_data_to_encrypt');
   ```
3. **Decryption:**

   ```javascript
   const decryptedData = await decrypt(secureKey, iv, encryptedData);
   ```

**API Reference**

- `encrypt(secureKey: string, iv: string, toBeEncrypted: string): Promise<string>`: Encrypts a string using the provided key and IV.
- `decrypt(secureKey: string, iv: string, toBeDecrypted: string): Promise<string>`: Decrypts a string using the provided key and IV.
- `generateSecureKey(password: string): Promise<string>`: Generates a secure key from a password.
- `generateSecureIV(password: string): Promise<string>`: Generates a secure initialization vector (IV) from a password.

**Error Handling**

- The `encrypt` and `decrypt` functions reject promises with informative error messages if the key or IV lengths are invalid.
- The `IV` length should be 16
- The `SecrueKey` length should be 32

**Security Considerations**

- Always store keys and IVs securely. Avoid hardcoding them in your code.

**Example**

A basic example of encrypting and decrypting data can be found in the example folder.

**License**

This library is licensed under the  ([MIT License](https://github.com/pandiaraj44/react-native-aes-256/blob/main/LICENSE)).
