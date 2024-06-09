package com.aes256;

import android.util.Log;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.module.annotations.ReactModule;

@ReactModule(name = Aes256Module.NAME)
public class Aes256Module extends ReactContextBaseJavaModule {
  public static final String NAME = "Aes256";

  public Aes256Module(ReactApplicationContext reactContext) {
    super(reactContext);
  }

  @Override
  @NonNull
  public String getName() {
    return NAME;
  }

  @ReactMethod
  public void encrypt(String secureKey, String iv, String toBeEncrypted, Promise promise) {
      try {
          String encryptedText = Aes256.encrypt(secureKey, iv, toBeEncrypted);
          promise.resolve(encryptedText);
      } catch (Exception e) {
          Log.e(NAME, "Encryption failed", e);
        promise.reject("Encryption failed" + e.getMessage());
      }
  }

  @ReactMethod
  public void decrypt(String secureKey, String iv, String toBeDecrypted, Promise promise) {
    try {
      String decryptedText = Aes256.decrypt(secureKey, iv, toBeDecrypted);
      promise.resolve(decryptedText);
    } catch (Exception e) {
      Log.e(NAME, "Decryption failed : ", e);
      promise.reject("Decryption failed : " + e.getMessage());
    }
  }

  @ReactMethod
  public void generateSecureKey(String password, Promise promise) {
    try {
      String secureKey = Aes256.generateSecureKey(password);
      promise.resolve(secureKey);
    } catch (Exception e) {
      Log.e(NAME, "Failed to generate secure key : ", e);
      promise.reject("Failed to generate secure key : " + e.getMessage());
    }
  }

  @ReactMethod
  public void generateSecureIV(String password, Promise promise) {
    try {
      String secureIV = Aes256.generateSecureIV(password);
      promise.resolve(secureIV);
    } catch (Exception e) {
      Log.e(NAME, "Failed to generate secure IV : ", e);
      promise.reject("Failed to generate secure IV : " + e.getMessage());
    }
  }
}
