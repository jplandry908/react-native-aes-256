import { NativeModules, Platform } from 'react-native';

const LINKING_ERROR =
  `The package 'react-native-aes-256' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n';

const Aes256 = NativeModules.Aes256
  ? NativeModules.Aes256
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    );

export function encrypt(
  secureKey: string,
  iv: string,
  toBeEncrypted: string
): Promise<string> {
  if (secureKey?.length !== 32) {
    return Promise.reject('Invalid secure key, length should be 32');
  }
  if (iv?.length !== 16) {
    return Promise.reject('Invalid secure IV, length should be 16');
  }
  return Aes256.encrypt(secureKey, iv, toBeEncrypted);
}

export function decrypt(
  secureKey: string,
  iv: string,
  toBeDecrypted: string
): Promise<string> {
  if (secureKey?.length !== 32) {
    return Promise.reject('Invalid secure key, length should be 32');
  }
  if (iv?.length !== 16) {
    return Promise.reject('Invalid secure IV, length should be 16');
  }
  return Aes256.decrypt(secureKey, iv, toBeDecrypted);
}

export function generateSecureKey(password: string): Promise<string> {
  return Aes256.generateSecureKey(password);
}

export function generateSecureIV(password: string): Promise<string> {
  return Aes256.generateSecureIV(password);
}
