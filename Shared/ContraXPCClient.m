#import "ContraXPCClient.h"

#ifndef NSXPCConnectionPrivileged
#define NSXPCConnectionPrivileged (1UL << 12)
#endif

@interface NSXPCConnection (Private)
- (instancetype)initWithMachServiceName:(NSString *)name options:(NSXPCConnectionOptions)options;
@end

@implementation ContraXPCClient {
    NSXPCConnection *_connection;
    dispatch_queue_t _lockQueue;
}

+ (instancetype)sharedClient {
    static ContraXPCClient *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[self alloc] init];
    });
    return shared;
}

- (instancetype)init {
    if (self = [super init]) {
        _lockQueue = dispatch_queue_create("com.kurishu.contraxpc.lock", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (NSXPCConnection *)connection {
    __block NSXPCConnection *conn = nil;
    dispatch_sync(_lockQueue, ^{
        if (!self->_connection) {
            self->_connection = [[NSXPCConnection alloc] initWithMachServiceName:@"com.kurishu.contrainstalld" options:NSXPCConnectionPrivileged];
            self->_connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ContraInstallerProtocol)];
            
            typeof(self) weakSelf = self;
            self->_connection.invalidationHandler = ^{
                typeof(self) strongSelf = weakSelf;
                if (strongSelf) {
                    dispatch_async(strongSelf->_lockQueue, ^{
                        strongSelf->_connection = nil;
                    });
                }
            };
            self->_connection.interruptionHandler = ^{
                NSLog(@"[ContraXPC] Connection interrupted.");
            };
            [self->_connection resume];
        }
        conn = self->_connection;
    });
    return conn;
}

- (void)installIPA:(NSString *)ipaPath completion:(void (^)(NSError * _Nullable error))completion {
    id<ContraInstallerProtocol> proxy = [[self connection] remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull xpcError) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(xpcError);
        });
    }];
    
    [proxy installIpaAtPath:ipaPath withReply:^(NSError * _Nullable installError) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(installError);
        });
    }];
}

- (void)uninstallAppWithBundleID:(NSString *)bundleID completion:(void (^)(NSError * _Nullable error))completion {
    id<ContraInstallerProtocol> proxy = [[self connection] remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull xpcError) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(xpcError);
        });
    }];
    
    [proxy uninstallAppWithBundleId:bundleID withReply:^(NSError * _Nullable uninstallError) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(uninstallError);
        });
    }];
}

- (void)fetchPathsForBundleID:(NSString *)bundleID completion:(void (^)(NSDictionary<NSString *, NSString *> * _Nullable info))completion {
    id<ContraInstallerProtocol> proxy = [[self connection] remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull xpcError) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(nil);
        });
    }];
    
    [proxy getPathsForBundleId:bundleID withReply:^(NSDictionary<NSString *,NSString *> * _Nullable info) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(info);
        });
    }];
}

- (void)fetchAllInstalledAppsWithCompletion:(void (^)(NSArray<NSDictionary<NSString *, NSString *> *> * _Nullable apps))completion {
    id<ContraInstallerProtocol> proxy = [[self connection] remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull xpcError) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(nil);
        });
    }];
    
    [proxy getAllInstalledAppsWithReply:^(NSArray<NSDictionary<NSString *, NSString *> *> * _Nullable apps) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(apps);
        });
    }];
}

- (void)getAppIconForBundleId:(NSString *)bundleId completion:(void (^)(NSData * _Nullable iconData))completion {
    id<ContraInstallerProtocol> proxy = [[self connection] remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull xpcError) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(nil);
        });
    }];
    
    // Assuming the protocol method is named `getAppIconForBundleId:withReply:`
    // If your protocol actually uses `completion:` instead of `withReply:`, swap `withReply:` for `completion:` below.
    [proxy getAppIconForBundleId:bundleId withReply:^(NSData * _Nullable iconData) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(iconData);
        });
    }];
}

- (void)loginAppleID:(NSString *)appleID
            password:(NSString *)password
          completion:(void (^)(BOOL requires2FA, NSString * _Nullable message, NSError * _Nullable error))completion {
    id<ContraInstallerProtocol> proxy = [[self connection] remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull xpcError) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(NO, nil, xpcError);
        });
    }];
    
    [proxy loginAppleID:appleID password:password withReply:^(BOOL requires2FA, NSString * _Nullable message, NSError * _Nullable error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(requires2FA, message, error);
        });
    }];
}

- (void)submit2FACode:(NSString *)code
           completion:(void (^)(BOOL success, NSString * _Nullable message, NSError * _Nullable error))completion {
    id<ContraInstallerProtocol> proxy = [[self connection] remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull xpcError) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(NO, nil, xpcError);
        });
    }];
    
    [proxy submit2FACode:code withReply:^(BOOL success, NSString * _Nullable message, NSError * _Nullable error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(success, message, error);
        });
    }];
}

- (void)fetchAccountStatusWithCompletion:(void (^)(NSDictionary<NSString *, id> * _Nullable accountInfo, NSError * _Nullable error))completion {
    id<ContraInstallerProtocol> proxy = [[self connection] remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull xpcError) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(nil, xpcError);
        });
    }];
    
    [proxy getAccountStatusWithReply:^(NSDictionary<NSString *, id> * _Nullable accountInfo, NSError * _Nullable error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(accountInfo, error);
        });
    }];
}

- (void)logoutWithCompletion:(void (^)(BOOL success, NSError * _Nullable error))completion {
    id<ContraInstallerProtocol> proxy = [[self connection] remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull xpcError) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(NO, xpcError);
        });
    }];
    
    [proxy logoutWithReply:^(BOOL success, NSError * _Nullable error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(success, error);
        });
    }];
}

- (void)testAnisetteWithCompletion:(void (^)(NSDictionary<NSString *, NSString *> * _Nullable headers, NSError * _Nullable error))completion {
    id<ContraInstallerProtocol> proxy = [[self connection] remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull xpcError) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(nil, xpcError);
        });
    }];
    
    [proxy testAnisetteWithReply:^(NSDictionary<NSString *, NSString *> * _Nullable headers, NSError * _Nullable error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(headers, error);
        });
    }];
}

- (void)resignIPA:(NSString *)ipaPath
       outputPath:(nullable NSString *)outputPath
            adhoc:(BOOL)adhoc
       completion:(void (^)(NSString * _Nullable finalPath, NSError * _Nullable error))completion {
    id<ContraInstallerProtocol> proxy = [[self connection] remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull xpcError) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(nil, xpcError);
        });
    }];
    
    [proxy resignIPAAtPath:ipaPath outputPath:outputPath adhoc:adhoc withReply:^(NSString * _Nullable finalPath, NSError * _Nullable error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (completion) completion(finalPath, error);
        });
    }];
}

- (nullable NSDictionary<NSString *, NSString *> *)fetchPathsSynchronouslyForBundleID:(NSString *)bundleID {
    __block NSDictionary<NSString *, NSString *> *resultInfo = nil;
    
    id<ContraInstallerProtocol> syncProxy = [[self connection] synchronousRemoteObjectProxyWithErrorHandler:^(NSError * _Nonnull xpcError) {
        NSLog(@"[ContraXPC] Sync XPC error: %@", xpcError.localizedDescription);
    }];
    
    [syncProxy getPathsForBundleId:bundleID withReply:^(NSDictionary<NSString *,NSString *> * _Nullable info) {
        resultInfo = info;
    }];
    
    return resultInfo;
}

@end
