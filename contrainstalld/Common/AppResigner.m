#import "AppResigner.h"
#import <rootless.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

@implementation AppResigner

+ (NSString *)executablePathForBundle:(NSString *)bundlePath {
    NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
    if (bundle.executablePath && [[NSFileManager defaultManager] fileExistsAtPath:bundle.executablePath]) {
        return bundle.executablePath;
    }
    
    NSString *plistPath = [bundlePath stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    NSString *exeName = info[@"CFBundleExecutable"];
    if (exeName) {
        NSString *candidate = [bundlePath stringByAppendingPathComponent:exeName];
        if ([[NSFileManager defaultManager] fileExistsAtPath:candidate]) {
            return candidate;
        }
    }
    
    NSString *baseName = [[bundlePath lastPathComponent] stringByDeletingPathExtension];
    NSString *candidate = [bundlePath stringByAppendingPathComponent:baseName];
    if ([[NSFileManager defaultManager] fileExistsAtPath:candidate]) {
        return candidate;
    }
    return nil;
}

+ (const char *)findLdidPath {
    const char *candidates[] = {
        ROOT_PATH("/usr/bin/ldid"),
        "/var/jb/usr/bin/ldid",
        "/usr/bin/ldid",
        ROOT_PATH("/usr/local/bin/ldid"),
        "/usr/local/bin/ldid"
    };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (access(candidates[i], X_OK) == 0) {
            return candidates[i];
        }
    }
    return NULL;
}

+ (BOOL)resignAppBundleAtPath:(NSString *)bundlePath withEntitlements:(NSString *)entitlementsPath error:(NSError **)error {
    const char *ldidPath = [self findLdidPath];
    if (!ldidPath) {
        if (error) *error = [self errorWithCode:404 message:@"ldid not found. Please install ldid from Sileo/Zebra."];
        return NO;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    
    if (![fm fileExistsAtPath:bundlePath]) {
        if (error) *error = [self errorWithCode:404 message:@"Bundle path does not exist."];
        return NO;
    }
    
    NSMutableSet<NSString *> *componentsToSign = [NSMutableSet set];
    NSDirectoryEnumerator *enumerator = [fm enumeratorAtPath:bundlePath];
    NSString *relativePath;
    
    while ((relativePath = [enumerator nextObject])) {
        NSString *fullPath = [bundlePath stringByAppendingPathComponent:relativePath];
        BOOL isDirectory = NO;
        [fm fileExistsAtPath:fullPath isDirectory:&isDirectory];
        
        if (isDirectory) {
            if ([relativePath hasSuffix:@".framework"] || [relativePath hasSuffix:@".appex"]) {
                NSString *exe = [self executablePathForBundle:fullPath];
                if (exe) {
                    [componentsToSign addObject:exe];
                }
            }
        } else {
            if ([relativePath hasSuffix:@".dylib"]) {
                [componentsToSign addObject:fullPath];
            }
        }
    }
    
    NSArray<NSString *> *sortedComponents = [componentsToSign.allObjects sortedArrayUsingComparator:^NSComparisonResult(NSString *obj1, NSString *obj2) {
        if (obj1.length > obj2.length) return NSOrderedAscending;
        if (obj1.length < obj2.length) return NSOrderedDescending;
        return NSOrderedSame;
    }];
    
    for (NSString *componentPath in sortedComponents) {
        BOOL success = [self executeLdidOnPath:componentPath withEntitlements:nil error:error];
        if (!success) {
            return NO;
        }
    }
    
    NSString *mainExecutable = [self executablePathForBundle:bundlePath];
    if (!mainExecutable) {
        if (error) *error = [self errorWithCode:500 message:@"Could not find main executable of app."];
        return NO;
    }
    
    return [self executeLdidOnPath:mainExecutable withEntitlements:entitlementsPath error:error];
}

+ (BOOL)repackPayloadAtDirectory:(NSString *)sourceDir toIPA:(NSString *)destinationIPA error:(NSError **)error {
    const char *zipPaths[] = {
        ROOT_PATH("/usr/bin/zip"),
        "/var/jb/usr/bin/zip",
        "/usr/bin/zip"
    };
    const char *foundZip = NULL;
    for (size_t i = 0; i < sizeof(zipPaths) / sizeof(zipPaths[0]); i++) {
        if (access(zipPaths[i], X_OK) == 0) {
            foundZip = zipPaths[i];
            break;
        }
    }
    
    if (!foundZip) {
        if (error) *error = [self errorWithCode:404 message:@"zip binary not found."];
        return NO;
    }
    
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    
    pid_t pid;
    char *argv[] = {
        (char *)foundZip,
        (char *)"-qr",
        (char *)destinationIPA.fileSystemRepresentation,
        (char *)"Payload",
        NULL
    };
    
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        chdir(sourceDir.fileSystemRepresentation);
    }
    
    int spawnError = posix_spawn(&pid, foundZip, &actions, NULL, argv, environ);
    if (cwd[0] != '\0') {
        chdir(cwd);
    }
    posix_spawn_file_actions_destroy(&actions);
    
    if (spawnError != 0) {
        if (error) *error = [self errorWithCode:spawnError message:@"posix_spawn failed for zip"];
        return NO;
    }
    
    int status;
    waitpid(pid, &status, 0);
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

+ (NSString *)extractEntitlementsFromPath:(NSString *)targetPath error:(NSError **)error {
    const char *ldidPath = [self findLdidPath];
    if (!ldidPath) {
        if (error) *error = [self errorWithCode:404 message:@"ldid not found for entitlement extraction."];
        return nil;
    }
    
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        if (error) *error = [self errorWithCode:errno message:@"Failed to create pipe for entitlement extraction."];
        return nil;
    }
    
    posix_spawn_file_actions_t file_actions;
    posix_spawn_file_actions_init(&file_actions);
    
    posix_spawn_file_actions_adddup2(&file_actions, pipefd[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&file_actions, pipefd[0]);
    
    const char *target = [targetPath UTF8String];
    char *argv[] = { (char *)ldidPath, (char *)"-e", (char *)target, NULL };
    
    pid_t pid;
    int spawnError = posix_spawn(&pid, ldidPath, &file_actions, NULL, argv, environ);
    
    posix_spawn_file_actions_destroy(&file_actions);
    
    if (spawnError != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        if (error) *error = [self errorWithCode:spawnError message:@"posix_spawn failed for ldid -e"];
        return nil;
    }
    
    close(pipefd[1]);
    
    NSMutableData *outputData = [NSMutableData data];
    char buffer[1024];
    ssize_t bytesRead;
    while ((bytesRead = read(pipefd[0], buffer, sizeof(buffer))) > 0) {
        [outputData appendBytes:buffer length:bytesRead];
    }
    close(pipefd[0]);
    
    int status;
    waitpid(pid, &status, 0);
    
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && outputData.length > 0) {
        NSString *outputString = [[NSString alloc] initWithData:outputData encoding:NSUTF8StringEncoding];
        if (outputString && [outputString containsString:@"<plist"]) {
            NSString *tempFileName = [NSString stringWithFormat:@"%@.plist", [[NSUUID UUID] UUIDString]];
            NSString *tempPath = [NSTemporaryDirectory() stringByAppendingPathComponent:tempFileName];
            
            if ([outputData writeToFile:tempPath atomically:YES]) {
                return tempPath;
            }
        }
    }
    
    return nil;
}

+ (BOOL)executeLdidOnPath:(NSString *)targetPath withEntitlements:(NSString *)entitlementsPath error:(NSError **)error {
    NSFileManager *fm = [NSFileManager defaultManager];
    const char *ldidPath = ROOT_PATH("/usr/bin/ldid");
    
    NSString *tempExtractedEntitlementsPath = nil;
    NSMutableArray *args = [NSMutableArray array];
    [args addObject:[NSString stringWithUTF8String:ldidPath]];
    
    if (entitlementsPath && [fm fileExistsAtPath:entitlementsPath]) {
        [args addObject:[NSString stringWithFormat:@"-S%@", entitlementsPath]];
    } else {
        tempExtractedEntitlementsPath = [self extractEntitlementsFromPath:targetPath error:nil];
        
        if (tempExtractedEntitlementsPath) {
            [args addObject:[NSString stringWithFormat:@"-S%@", tempExtractedEntitlementsPath]];
        } else {
            [args addObject:@"-S"];
        }
    }
    
    [args addObject:targetPath];
    
    int argc = (int)args.count;
    char **argv = (char **)malloc((argc + 1) * sizeof(char *));
    for (int i = 0; i < argc; i++) {
        argv[i] = strdup([args[i] UTF8String]);
    }
    argv[argc] = NULL;
    
    pid_t pid;
    int spawnError = posix_spawn(&pid, ldidPath, NULL, NULL, argv, environ);
    
    for (int i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);
    
    if (spawnError != 0) {
        if (tempExtractedEntitlementsPath) [fm removeItemAtPath:tempExtractedEntitlementsPath error:nil];
        if (error) *error = [self errorWithCode:spawnError message:[NSString stringWithFormat:@"posix_spawn failed: %d", spawnError]];
        return NO;
    }
    
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        if (tempExtractedEntitlementsPath) [fm removeItemAtPath:tempExtractedEntitlementsPath error:nil];
        if (error) *error = [self errorWithCode:errno message:@"waitpid failed."];
        return NO;
    }
    
    if (tempExtractedEntitlementsPath) {
        [fm removeItemAtPath:tempExtractedEntitlementsPath error:nil];
    }
    
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return YES;
    } else {
        if (error) *error = [self errorWithCode:WEXITSTATUS(status) message:[NSString stringWithFormat:@"ldid failed on %@ with status: %d", targetPath.lastPathComponent, WEXITSTATUS(status)]];
        return NO;
    }
}

+ (NSError *)errorWithCode:(NSInteger)code message:(NSString *)message {
    return [NSError errorWithDomain:@"com.kurishu.contrainstalld.AppResigner" 
                               code:code 
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}

@end
