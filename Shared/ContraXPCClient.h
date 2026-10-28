#import <Foundation/Foundation.h>
#import "ContraInstallerProtocol.h"

NS_ASSUME_NONNULL_BEGIN

@interface ContraXPCClient : NSObject

+ (instancetype)sharedClient;

// async for UI
- (void)installIPA:(NSString *)ipaPath completion:(void (^)(NSError * _Nullable error))completion;
- (void)uninstallAppWithBundleID:(NSString *)bundleID completion:(void (^)(NSError * _Nullable error))completion;
- (void)fetchPathsForBundleID:(NSString *)bundleID completion:(void (^)(NSDictionary<NSString *, NSString *> * _Nullable info))completion;
- (void)fetchAllInstalledAppsWithCompletion:(void (^)(NSArray<NSDictionary<NSString *, NSString *> *> * _Nullable apps))completion;
- (void)getAppIconForBundleId:(NSString *)bundleId completion:(void (^)(NSData * _Nullable iconData))completion;

// Apple ID & Authentication
- (void)loginAppleID:(NSString *)appleID
            password:(NSString *)password
          completion:(void (^)(BOOL requires2FA, NSString * _Nullable message, NSError * _Nullable error))completion;

- (void)submit2FACode:(NSString *)code
           completion:(void (^)(BOOL success, NSString * _Nullable message, NSError * _Nullable error))completion;

- (void)fetchAccountStatusWithCompletion:(void (^)(NSDictionary<NSString *, id> * _Nullable accountInfo, NSError * _Nullable error))completion;

- (void)logoutWithCompletion:(void (^)(BOOL success, NSError * _Nullable error))completion;

// Anisette Diagnostics
- (void)testAnisetteWithCompletion:(void (^)(NSDictionary<NSString *, NSString *> * _Nullable headers, NSError * _Nullable error))completion;

// Standalone Resigning
- (void)resignIPA:(NSString *)ipaPath
       outputPath:(nullable NSString *)outputPath
            adhoc:(BOOL)adhoc
       completion:(void (^)(NSString * _Nullable finalPath, NSError * _Nullable error))completion;

// sync for redirect
- (nullable NSDictionary<NSString *, NSString *> *)fetchPathsSynchronouslyForBundleID:(NSString *)bundleID;

@end

NS_ASSUME_NONNULL_END
