#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@protocol ContraInstallerProtocol <NSObject>

- (void)installIpaAtPath:(NSString *)path withReply:(void (^)(NSError * _Nullable error))reply;

- (void)uninstallAppWithBundleId:(NSString *)bundleId withReply:(void (^)(NSError * _Nullable error))reply;

- (void)getPathsForBundleId:(NSString *)bundleId withReply:(void (^)(NSDictionary<NSString *, NSString *> * _Nullable paths))reply;

- (void)getAllInstalledAppsWithReply:(void (^)(NSArray<NSDictionary<NSString *, NSString *> *> *apps))reply;

- (void)getAppIconForBundleId:(NSString *)bundleId withReply:(void (^)(NSData * _Nullable iconData))reply;

// Apple ID Authentication & Session (GhostSign / Fortiva Engine)
- (void)loginAppleID:(NSString *)appleID
            password:(NSString *)password
           withReply:(void (^)(BOOL requires2FA, NSString * _Nullable message, NSError * _Nullable error))reply;

- (void)submit2FACode:(NSString *)code
            withReply:(void (^)(BOOL success, NSString * _Nullable message, NSError * _Nullable error))reply;

- (void)getAccountStatusWithReply:(void (^)(NSDictionary<NSString *, id> * _Nullable accountInfo, NSError * _Nullable error))reply;

- (void)logoutWithReply:(void (^)(BOOL success, NSError * _Nullable error))reply;

// Anisette Diagnostics (Local akd attestation)
- (void)testAnisetteWithReply:(void (^)(NSDictionary<NSString *, NSString *> * _Nullable headers, NSError * _Nullable error))reply;

// Standalone Resigning (BridgeSigner Native Engine)
- (void)resignIPAAtPath:(NSString *)ipaPath
             outputPath:(nullable NSString *)outputPath
                  adhoc:(BOOL)adhoc
              withReply:(void (^)(NSString * _Nullable finalPath, NSError * _Nullable error))reply;

@end

NS_ASSUME_NONNULL_END
