#import <Foundation/Foundation.h>

@interface AppResigner : NSObject

+ (BOOL)resignAppBundleAtPath:(NSString *)bundlePath withEntitlements:(NSString *)entitlementsPath error:(NSError **)error;
+ (BOOL)repackPayloadAtDirectory:(NSString *)sourceDir toIPA:(NSString *)destinationIPA error:(NSError **)error;

@end
