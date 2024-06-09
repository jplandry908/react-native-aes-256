import { NativeModules } from 'react-native';
import {
  encrypt,
  decrypt,
  generateSecureKey,
  generateSecureIV,
} from '../index';

jest.mock('react-native', () => ({
  NativeModules: {
    Aes256: {
      encrypt: jest.fn(),
      decrypt: jest.fn(),
      generateSecureKey: jest.fn(),
      generateSecureIV: jest.fn(),
    },
  },
  Platform: {
    select: jest.fn((selection) => selection.default),
  },
}));

describe('Aes256 module', () => {
  const secureKey = '12345678901234567890123456789012';
  const secureIV = '1234567890123456';
  const text = 'Hello, World!';
  const encryptedText = 'encryptedText';
  const decryptedText = 'Hello, World!';
  const password = 'password';
  const LINKING_ERROR = `The package 'react-native-aes-256' doesn't seem to be linked. Make sure: \n\n- You rebuilt the app after installing the package\n- You are not using Expo Go\n`;

  beforeEach(() => {
    NativeModules.Aes256.encrypt.mockReset();
    NativeModules.Aes256.decrypt.mockReset();
    NativeModules.Aes256.generateSecureKey.mockReset();
    NativeModules.Aes256.generateSecureIV.mockReset();
  });

  describe('encrypt function', () => {
    it('should encrypt text successfully', async () => {
      NativeModules.Aes256.encrypt.mockResolvedValue(encryptedText);
      const result = await encrypt(secureKey, secureIV, text);
      expect(result).toBe(encryptedText);
      expect(NativeModules.Aes256.encrypt).toHaveBeenCalledWith(
        secureKey,
        secureIV,
        text
      );
    });

    it('should throw error for invalid secure key length', async () => {
      await expect(encrypt('invalidKey', secureIV, text)).rejects.toEqual(
        'Invalid secure key, length should be 32'
      );
    });

    it('should throw error for invalid IV length', async () => {
      await expect(encrypt(secureKey, 'invalidIV', text)).rejects.toEqual(
        'Invalid secure IV, length should be 16'
      );
    });
  });

  describe('decrypt function', () => {
    it('should decrypt text successfully', async () => {
      NativeModules.Aes256.decrypt.mockResolvedValue(decryptedText);
      const result = await decrypt(secureKey, secureIV, encryptedText);
      expect(result).toBe(decryptedText);
      expect(NativeModules.Aes256.decrypt).toHaveBeenCalledWith(
        secureKey,
        secureIV,
        encryptedText
      );
    });

    it('should throw error for invalid secure key length', async () => {
      await expect(
        decrypt('invalidKey', secureIV, encryptedText)
      ).rejects.toEqual('Invalid secure key, length should be 32');
    });

    it('should throw error for invalid IV length', async () => {
      await expect(
        decrypt(secureKey, 'invalidIV', encryptedText)
      ).rejects.toEqual('Invalid secure IV, length should be 16');
    });
  });

  describe('generateSecureKey function', () => {
    it('should generate secure key successfully', async () => {
      NativeModules.Aes256.generateSecureKey.mockResolvedValue(secureKey);
      const result = await generateSecureKey(password);
      expect(result).toBe(secureKey);
      expect(NativeModules.Aes256.generateSecureKey).toHaveBeenCalledWith(
        password
      );
    });
  });

  describe('generateSecureIV function', () => {
    it('should generate secure IV successfully', async () => {
      NativeModules.Aes256.generateSecureIV.mockResolvedValue(secureIV);
      const result = await generateSecureIV(password);
      expect(result).toBe(secureIV);
      expect(NativeModules.Aes256.generateSecureIV).toHaveBeenCalledWith(
        password
      );
    });
  });

  describe('Native module linking', () => {
    it('should throw error if Aes256 module is not linked', () => {
      jest.resetModules();
      jest.mock('react-native', () => ({
        NativeModules: {},
        Platform: {
          select: jest.fn((selection) => selection.default),
        },
      }));

      const Aes256Module = require('../index');
      const { encrypt: encryptModule } = Aes256Module;

      expect(() => encryptModule(secureKey, secureIV, text)).toThrowError(
        new Error(LINKING_ERROR)
      );
    });
  });
});
