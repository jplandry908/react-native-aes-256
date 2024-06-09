  import Foundation
  import CommonCrypto
  import Security


  @objc(Aes256)
  class Aes256: NSObject {
    
    static let PBKDF2_ITERATION_COUNT = 1001;
    static let PBKDF2_KEY_LENGTH = 256;
    static let SECURE_IV_LENGTH = 8;
    static let SECURE_KEY_LENGTH = 16;
    
    @objc
     static func requiresMainQueueSetup() -> Bool {
       return true
    }
    
    @objc
    func encrypt(_ secureKey: String, iv: String, toBeEncrypted: String, resolver: @escaping RCTPromiseResolveBlock, rejecter: @escaping RCTPromiseRejectBlock) {
      do {
        let encryptedData = try aesEncrypt(text: toBeEncrypted, key: secureKey, iv: iv)
        resolver(encryptedData.base64EncodedString())
      } catch {
        rejecter("ENCRYPTION_ERROR", "Encryption failed", error)
      }
    }

    @objc
    func decrypt(_ secureKey: String, iv: String, toBeDecrypted: String, resolver: @escaping RCTPromiseResolveBlock, rejecter: @escaping RCTPromiseRejectBlock) {
      guard let data = Data(base64Encoded: toBeDecrypted) else {
        rejecter("DECRYPTION_ERROR", "Invalid base64 string", nil)
        return
      }
      do {
        let decryptedText = try aesDecrypt(data: data, key: secureKey, iv: iv)
        resolver(decryptedText)
      } catch {
        rejecter("DECRYPTION_ERROR", "Decryption failed", error)
      }
    }
    
    @objc
    func generateSecureKey(_ password: String, resolver: @escaping RCTPromiseResolveBlock, rejecter: @escaping RCTPromiseRejectBlock) {
      do {
        let secureKey = try pbkdf2(password: password, salt: generateRandomSalt(length: 16)!, keyLength: Aes256.SECURE_KEY_LENGTH, iterations: Aes256.PBKDF2_ITERATION_COUNT)
        resolver(hexEncode(data: secureKey))
      } catch {
        rejecter("KEY_GENERATION_ERROR", "Securekey generation failed", error)
      }
    }
    
    @objc
    func generateSecureIV(_ password: String, resolver: @escaping RCTPromiseResolveBlock, rejecter: @escaping RCTPromiseRejectBlock) {
      do {
        let secureIv = try pbkdf2(password: password, salt: generateRandomSalt(length: 16)!, keyLength: Aes256.SECURE_IV_LENGTH, iterations: Aes256.PBKDF2_ITERATION_COUNT)
        resolver(hexEncode(data: secureIv))
      } catch {
        rejecter("KEY_GENERATION_ERROR", "Securekey generation failed", error)
      }
    }

    private func aesEncrypt(text: String, key: String, iv: String) throws -> Data {
      guard let data = text.data(using: .utf8),
            let keyData = key.data(using: .utf8),
            let ivData = iv.data(using: .utf8) else {
        throw NSError(domain: "InvalidInput", code: 0, userInfo: nil)
      }

      var keyBytes = [UInt8](repeating: 0, count: kCCKeySizeAES256)
      keyData.copyBytes(to: &keyBytes, count: min(keyData.count, kCCKeySizeAES256))

      var ivBytes = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
      ivData.copyBytes(to: &ivBytes, count: min(ivData.count, kCCBlockSizeAES128))

      let encryptedData = try performAESCryptoOperation(operation: CCOperation(kCCEncrypt), data: data, keyBytes: &keyBytes, ivBytes: &ivBytes)
      return encryptedData
    }

    private func aesDecrypt(data: Data, key: String, iv: String) throws -> String {
      guard let keyData = key.data(using: .utf8),
            let ivData = iv.data(using: .utf8) else {
        throw NSError(domain: "InvalidInput", code: 0, userInfo: nil)
      }

      var keyBytes = [UInt8](repeating: 0, count: kCCKeySizeAES256)
      keyData.copyBytes(to: &keyBytes, count: min(keyData.count, kCCKeySizeAES256))

      var ivBytes = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
      ivData.copyBytes(to: &ivBytes, count: min(ivData.count, kCCBlockSizeAES128))

      let decryptedData = try performAESCryptoOperation(operation: CCOperation(kCCDecrypt), data: data, keyBytes: &keyBytes, ivBytes: &ivBytes)
      guard let decryptedText = String(data: decryptedData, encoding: .utf8) else {
        throw NSError(domain: "DecryptionError", code: 0, userInfo: nil)
      }

      return decryptedText
    }

    private func performAESCryptoOperation(operation: CCOperation, data: Data, keyBytes: inout [UInt8], ivBytes: inout [UInt8]) throws -> Data {
      var numBytesEncrypted = 0
      var encryptedData = Data(count: data.count + kCCBlockSizeAES128)

      // Copy encryptedData to a temporary variable to avoid overlapping access
      let encryptedDataLength = encryptedData.count
      var encryptedDataCopy = encryptedData // Copy to prevent modification overlap

      let cryptStatus = encryptedDataCopy.withUnsafeMutableBytes { encryptedBytes in
        data.withUnsafeBytes { dataBytes in
          CCCrypt(
            operation,
            CCAlgorithm(kCCAlgorithmAES128),
            CCOptions(kCCOptionPKCS7Padding),
            &keyBytes,
            kCCKeySizeAES256,
            &ivBytes,
            dataBytes.baseAddress,
            data.count,
            encryptedBytes.baseAddress,
            encryptedDataLength,
            &numBytesEncrypted
          )
        }
      }

      guard cryptStatus == kCCSuccess else {
        throw NSError(domain: "CryptoError", code: Int(cryptStatus), userInfo: nil)
      }

      // Copy the result back to encryptedData to return it
      encryptedData = encryptedDataCopy.subdata(in: 0..<numBytesEncrypted)
      return encryptedData
    }
    
    private enum PBKDF2Error: Error {
        case keyDerivationFailed
    }

    private func pbkdf2(password: String, salt: Data, keyLength: Int, iterations: Int) throws -> Data {
        // Convert password to Data
        let passwordData = Data(password.utf8)
        
        // Prepare a buffer to hold the derived key
        var derivedKey = Data(repeating: 0, count: keyLength)
        
        // Perform the key derivation using PBKDF2 and HMAC-SHA256
        let result = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
            salt.withUnsafeBytes { saltBytes in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2), // PBKDF2 key derivation algorithm
                    password, // Password
                    passwordData.count, // Length of password
                    saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), // Salt
                    salt.count, // Length of salt
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), // HMAC-SHA256
                    UInt32(iterations), // Iterations
                    derivedKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), // Buffer for the derived key
                    keyLength // Length of the derived key
                )
            }
        }
        // Check the result and throw an error if key derivation failed
        if result != kCCSuccess {
            throw PBKDF2Error.keyDerivationFailed
        }
        
        return derivedKey
    }
    
    private func generateRandomSalt(length: Int) -> Data? {
        var salt = Data(count: length) // Initialize a Data object with the desired length

        // Use `withUnsafeMutableBytes` to access the underlying bytes of the Data object
        let result = salt.withUnsafeMutableBytes { saltBytes in
            // Generate random bytes and store them in the salt
            SecRandomCopyBytes(kSecRandomDefault, length, saltBytes.baseAddress!)
        }

        // Check the result and return the salt if successful, or nil if there was an error
        return result == errSecSuccess ? salt : nil
    }
    
    private func hexEncode(data: Data) -> String {
        return data.map { String(format: "%02hhx", $0) }.joined()
    }
  }
