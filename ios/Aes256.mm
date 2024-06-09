#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(Aes256, NSObject)

RCT_EXTERN_METHOD(encrypt:(NSString *)secureKey iv:(NSString *)iv toBeEncrypted:(NSString *)toBeEncrypted resolver:(RCTPromiseResolveBlock)resolver rejecter:(RCTPromiseRejectBlock)rejecter)

RCT_EXTERN_METHOD(decrypt:(NSString *)secureKey iv:(NSString *)iv toBeDecrypted:(NSString *)toBeDecrypted resolver:(RCTPromiseResolveBlock)resolver rejecter:(RCTPromiseRejectBlock)rejecter)

RCT_EXTERN_METHOD(generateSecureKey:(NSString *)password resolver:(RCTPromiseResolveBlock)resolver rejecter:(RCTPromiseRejectBlock)rejecter)

RCT_EXTERN_METHOD(generateSecureIV:(NSString *)password resolver:(RCTPromiseResolveBlock)resolver rejecter:(RCTPromiseRejectBlock)rejecter)

@end
