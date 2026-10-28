#import <Foundation/Foundation.h>
#import <stdio.h>
#import <stdlib.h>
#import <unistd.h>
#import <signal.h>
#import <sys/stat.h>
#import <limits.h>
#import <fcntl.h>

#import "ContraXPCClient.h"

#define CT_VERSION "0.1.0"

#pragma mark - Terminal Colors & Styling

static BOOL gIsTTY = NO;

static inline const char *colReset(void)  { return gIsTTY ? "\033[0m" : ""; }
static inline const char *colBold(void)   { return gIsTTY ? "\033[1m" : ""; }
static inline const char *colRed(void)    { return gIsTTY ? "\033[1;31m" : ""; }
static inline const char *colGreen(void)  { return gIsTTY ? "\033[1;32m" : ""; }
static inline const char *colYellow(void) { return gIsTTY ? "\033[1;33m" : ""; }
static inline const char *colCyan(void)   { return gIsTTY ? "\033[1;36m" : ""; }
static inline const char *colGray(void)   { return gIsTTY ? "\033[90m" : ""; }

#pragma mark - Signal Handling

static volatile sig_atomic_t gInterrupted = 0;

static void handleSignal(int sig) {
    (void)sig;
    gInterrupted = 1;
    if (gIsTTY) {
        fprintf(stderr, "\r\033[K\n%s[!] Operation interrupted by user.%s\n", colYellow(), colReset());
    } else {
        fprintf(stderr, "\nOperation interrupted by user.\n");
    }
    _exit(130);
}

static void setupSignalHandlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handleSignal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

#pragma mark - RunLoop Event Pump (Async XPC Execution)

// Pump main runloop to process XPC reply handlers dispatched to main queue
typedef void (^CTAsyncWorkBlock)(void (^doneBlock)(int exitCode));

static int runAsyncWithSpinner(NSString *message, NSTimeInterval timeout, CTAsyncWorkBlock work) {
    __block BOOL isDone = NO;
    __block int resultExitCode = 0;

    const char *spinnerChars[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
    const int spinnerCount = sizeof(spinnerChars) / sizeof(spinnerChars[0]);
    int frame = 0;

    if (!gIsTTY && message) {
        printf("[*] %s\n", message.UTF8String);
        fflush(stdout);
    }

    work(^(int code) {
        resultExitCode = code;
        isDone = YES;
    });

    NSTimeInterval startTime = [NSDate timeIntervalSinceReferenceDate];

    while (!isDone && !gInterrupted) {
        @autoreleasepool {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                     beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.08]];
        }

        NSTimeInterval elapsed = [NSDate timeIntervalSinceReferenceDate] - startTime;

        if (timeout > 0 && elapsed > timeout) {
            if (gIsTTY) {
                printf("\r\033[K");
            }
            fprintf(stderr, "%s[-] Error:%s Operation timed out after %.0fs.\n", colRed(), colReset(), timeout);
            return 1;
        }

        if (gIsTTY && message && !isDone) {
            printf("\r\033[K%s[%s]%s %s %s(%.1fs)%s",
                   colCyan(),
                   spinnerChars[frame % spinnerCount],
                   colReset(),
                   message.UTF8String,
                   colGray(),
                   elapsed,
                   colReset());
            fflush(stdout);
            frame++;
        }
    }

    if (gIsTTY && message) {
        printf("\r\033[K");
        fflush(stdout);
    }

    return resultExitCode;
}

static int runAsyncWithDirectWait(NSTimeInterval timeout, CTAsyncWorkBlock work) {
    __block BOOL isDone = NO;
    __block int resultExitCode = 0;

    work(^(int code) {
        resultExitCode = code;
        isDone = YES;
    });

    NSTimeInterval startTime = [NSDate timeIntervalSinceReferenceDate];

    while (!isDone && !gInterrupted) {
        @autoreleasepool {
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                     beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
        }

        NSTimeInterval elapsed = [NSDate timeIntervalSinceReferenceDate] - startTime;
        if (timeout > 0 && elapsed > timeout) {
            fprintf(stderr, "%s[-] Error:%s Operation timed out after %.0fs.\n", colRed(), colReset(), timeout);
            return 1;
        }
    }

    return resultExitCode;
}

#pragma mark - Realtime Log Tailer & Colored Formatting

static const char *getAuthLogFilePath(void) {
    static char sPath[PATH_MAX] = {0};
    if (sPath[0] != '\0') return sPath;

    const char *candidates[] = {
        "/var/jb/tmp/contra_auth_debug.log",
        "/tmp/contra_auth_debug.log",
        "/var/tmp/contra_auth_debug.log"
    };
    for (int i = 0; i < 3; i++) {
        if (access(candidates[i], F_OK) == 0) {
            strncpy(sPath, candidates[i], sizeof(sPath) - 1);
            return sPath;
        }
    }
    if (access("/var/jb", F_OK) == 0) {
        strncpy(sPath, "/var/jb/tmp/contra_auth_debug.log", sizeof(sPath) - 1);
    } else {
        strncpy(sPath, "/tmp/contra_auth_debug.log", sizeof(sPath) - 1);
    }
    return sPath;
}

static void printColoredLogLine(const char *rawLine) {
    if (!rawLine || strlen(rawLine) == 0) return;

    if (strstr(rawLine, "[ANISETTE]")) {
        printf("%s%s%s", "\033[1;35m", rawLine, colReset());
    } else if (strstr(rawLine, "[SRP-6a]")) {
        printf("%s%s%s", "\033[1;33m", rawLine, colReset());
    } else if (strstr(rawLine, "[GSA-HTTP]")) {
        printf("%s%s%s", "\033[1;36m", rawLine, colReset());
    } else if (strstr(rawLine, "[2FA-PUSH]")) {
        printf("%s%s%s", "\033[1;31m", rawLine, colReset());
    } else if (strstr(rawLine, "[2FA-CODE]")) {
        printf("%s%s%s", "\033[1;32m", rawLine, colReset());
    } else if (strstr(rawLine, "[DEV-TEAM]")) {
        printf("%s%s%s", "\033[1;96m", rawLine, colReset());
    } else if (strstr(rawLine, "[SESSION]")) {
        printf("%s%s%s", "\033[1;34m", rawLine, colReset());
    } else if (strstr(rawLine, "[AUTH]")) {
        printf("%s%s%s", "\033[1;37m", rawLine, colReset());
    } else {
        printf("%s%s%s", colGray(), rawLine, colReset());
    }
    fflush(stdout);
}

static dispatch_source_t gLogTailerSource = NULL;
static off_t gLogTailerOffset = 0;

static void startRealtimeLogTailer(void) {
    const char *path = getAuthLogFilePath();
    unlink(path);

    gLogTailerOffset = 0;
    dispatch_queue_t tailerQueue = dispatch_queue_create("com.kurishu.contra.logtailer", DISPATCH_QUEUE_SERIAL);
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, tailerQueue);
    dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, 50 * NSEC_PER_MSEC, 10 * NSEC_PER_MSEC);

    dispatch_source_set_event_handler(timer, ^{
        const char *logPath = getAuthLogFilePath();
        int fd = open(logPath, O_RDONLY);
        if (fd < 0) return;

        struct stat st;
        if (fstat(fd, &st) == 0 && st.st_size > gLogTailerOffset) {
            lseek(fd, gLogTailerOffset, SEEK_SET);
            char buffer[4096];
            ssize_t bytesRead = 0;
            while ((bytesRead = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
                buffer[bytesRead] = '\0';
                gLogTailerOffset += bytesRead;

                char *saveptr = NULL;
                char *line = strtok_r(buffer, "\n", &saveptr);
                while (line != NULL) {
                    printColoredLogLine(line);
                    printf("\n");
                    line = strtok_r(NULL, "\n", &saveptr);
                }
            }
        }
        close(fd);
    });

    gLogTailerSource = timer;
    dispatch_resume(timer);
}

static void stopRealtimeLogTailer(void) {
    if (gLogTailerSource) {
        dispatch_source_cancel(gLogTailerSource);
        gLogTailerSource = NULL;
    }
    const char *logPath = getAuthLogFilePath();
    int fd = open(logPath, O_RDONLY);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0 && st.st_size > gLogTailerOffset) {
            lseek(fd, gLogTailerOffset, SEEK_SET);
            char buffer[4096];
            ssize_t bytesRead = 0;
            while ((bytesRead = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
                buffer[bytesRead] = '\0';
                gLogTailerOffset += bytesRead;

                char *saveptr = NULL;
                char *line = strtok_r(buffer, "\n", &saveptr);
                while (line != NULL) {
                    printColoredLogLine(line);
                    printf("\n");
                    line = strtok_r(NULL, "\n", &saveptr);
                }
            }
        }
        close(fd);
    }
}

static void printAccountSuccessCard(NSDictionary<NSString *, id> *info) {
    NSString *appleID = info[@"appleID"] ?: @"(Unknown)";
    NSString *dsid = info[@"dsid"] ?: @"(Unknown)";
    NSString *teamName = info[@"teamName"] ?: @"Personal Team";
    NSString *teamID = info[@"teamID"] ?: @"(None)";
    NSArray *teams = info[@"teams"];

    printf("\n");
    printf("%s┌────────────────────────────────────────────────────────────────────────┐%s\n", colCyan(), colReset());
    printf("%s│%s  %s✅ Apple ID Authentication Successful%s                               %s│%s\n", colCyan(), colReset(), colBold(), colReset(), colCyan(), colReset());
    printf("%s├────────────────────────────────────────────────────────────────────────┤%s\n", colCyan(), colReset());
    printf("%s│%s  %-14s: %s%-49s%s%s│%s\n", colCyan(), colReset(), "Apple ID", colBold(), appleID.UTF8String, colReset(), colCyan(), colReset());
    printf("%s│%s  %-14s: %-49s%s│%s\n", colCyan(), colReset(), "DSID", dsid.UTF8String, colCyan(), colReset());
    printf("%s│%s  %-14s: %s%-49s%s%s│%s\n", colCyan(), colReset(), "Team Name", colGreen(), teamName.UTF8String, colReset(), colCyan(), colReset());
    printf("%s│%s  %-14s: %s%-49s%s%s│%s\n", colCyan(), colReset(), "Team ID", colGreen(), teamID.UTF8String, colReset(), colCyan(), colReset());
    printf("%s│%s  %-14s: %-49s%s│%s\n", colCyan(), colReset(), "Session", "Active (Credentials persisted to session.plist)", colCyan(), colReset());
    printf("%s└────────────────────────────────────────────────────────────────────────┘%s\n", colCyan(), colReset());

    if ([teams isKindOfClass:[NSArray class]] && teams.count > 1) {
        printf("\n%sAll Associated Teams (%lu):%s\n", colBold(), (unsigned long)teams.count, colReset());
        for (NSDictionary *t in teams) {
            NSString *tid = t[@"teamId"] ?: @"";
            NSString *tname = t[@"name"] ?: @"";
            NSString *ttype = t[@"type"] ?: @"";
            printf("  • %s%s%s [ID: %s%s%s] (%s)\n",
                   colCyan(), tname.UTF8String, colReset(),
                   colGreen(), tid.UTF8String, colReset(),
                   ttype.UTF8String);
        }
    }
    printf("\n");
}

static int cmdAuthLog(void) {
    const char *logPath = getAuthLogFilePath();
    FILE *f = fopen(logPath, "r");
    if (!f) {
        printf("%s[!] No recent authentication log found at: %s%s\n", colYellow(), logPath, colReset());
        return 0;
    }
    printf("%sAuthentication Debug Trace Log (%s):%s\n", colBold(), logPath, colReset());
    printf("%s────────────────────────────────────────────────────────────────────────%s\n", colGray(), colReset());
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        printColoredLogLine(line);
        printf("\n");
    }
    fclose(f);
    printf("%s────────────────────────────────────────────────────────────────────────%s\n", colGray(), colReset());
    return 0;
}

#pragma mark - Commands Implementation

static void printUsage(const char *progName) {
    printf("%s%sContraStore CLI (ct)%s - Rootless App Management & Sideloading Tool\n\n", colBold(), colCyan(), colReset());
    printf("%sUSAGE:%s\n", colBold(), colReset());
    printf("  %s <command> [options] [arguments]\n\n", progName);
    printf("%sCOMMANDS:%s\n", colBold(), colReset());
    printf("  %sinstall%s <path.ipa> [more.ipa...]       Install one or more IPA packages\n", colGreen(), colReset());
    printf("  %suninstall%s, %srm%s <bundle-id> [more...]     Uninstall an application by bundle identifier\n", colGreen(), colReset(), colGreen(), colReset());
    printf("  %slist%s, %sls%s                                List all applications managed by ContraStore\n", colGreen(), colReset(), colGreen(), colReset());
    printf("  %sinfo%s, %spaths%s <bundle-id>                 Inspect container and redirect paths for an app\n", colGreen(), colReset(), colGreen(), colReset());
    printf("  %slogin%s [apple-id] [--debug / -v]             Authenticate with Apple ID (SRP-6a + 2FA Push)\n", colGreen(), colReset());
    printf("  %slogout%s                                      Sign out and remove saved session\n", colGreen(), colReset());
    printf("  %swhoami%s, %saccount%s, %sstatus%s              Show active Apple ID session and team info\n", colGreen(), colReset(), colGreen(), colReset(), colGreen(), colReset());
    printf("  %sanisette%s                                    Test on-device genuine Anisette attestation (akd)\n", colGreen(), colReset());
    printf("  %sauth-log%s, %slog%s                            Dump realtime authentication debug trace log\n", colGreen(), colReset(), colGreen(), colReset());
    printf("  %ssign%s <path.ipa> [-o out.ipa] [--adhoc]      Resign an IPA package using Apple ID or Ad-Hoc\n", colGreen(), colReset());
    printf("  %sversion%s, %s-v%s, %s--version%s               Show version information\n", colGreen(), colReset(), colGreen(), colReset(), colGreen(), colReset());
    printf("  %shelp%s, %s-h%s, %s--help%s                     Show this help message\n\n", colGreen(), colReset(), colGreen(), colReset(), colGreen(), colReset());
    printf("%sEXAMPLES:%s\n", colBold(), colReset());
    printf("  %s install MyApp.ipa\n", progName);
    printf("  %s login user@example.com --debug\n", progName);
    printf("  %s whoami\n", progName);
    printf("  %s anisette\n", progName);
    printf("  %s sign MyApp.ipa -o MyApp-signed.ipa\n", progName);
    printf("  %s uninstall com.example.app\n", progName);
    printf("  %s list\n\n", progName);
}

static void printVersion(void) {
    printf("%sct (ContraStore CLI)%s version %s\n", colBold(), colReset(), CT_VERSION);
    printf("Target Architecture: arm64 / arm64e (iOS Rootless)\n");
}

static int cmdInstall(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "%s[-] Error:%s Missing IPA path.\n", colRed(), colReset());
        fprintf(stderr, "Usage: %s install <path.ipa> [more.ipa...]\n", argv[0]);
        return 1;
    }

    int totalFiles = argc - 2;
    int successCount = 0;
    int failureCount = 0;

    for (int i = 2; i < argc; i++) {
        NSString *rawPath = [NSString stringWithUTF8String:argv[i]];
        NSString *expandedPath = [rawPath stringByExpandingTildeInPath];

        char resolvedBuffer[PATH_MAX];
        NSString *canonicalPath = nil;
        if (realpath(expandedPath.fileSystemRepresentation, resolvedBuffer) != NULL) {
            canonicalPath = [NSString stringWithUTF8String:resolvedBuffer];
        } else {
            canonicalPath = expandedPath.stringByStandardizingPath;
        }

        BOOL isDir = NO;
        if (![[NSFileManager defaultManager] fileExistsAtPath:canonicalPath isDirectory:&isDir] || isDir) {
            fprintf(stderr, "%s[-] Error:%s IPA file not found at: '%s'\n", colRed(), colReset(), argv[i]);
            failureCount++;
            continue;
        }

        if (![canonicalPath.pathExtension.lowercaseString isEqualToString:@"ipa"]) {
            fprintf(stderr, "%s[-] Error:%s '%s' is not an .ipa file package.\n", colRed(), colReset(), argv[i]);
            failureCount++;
            continue;
        }

        NSString *filename = canonicalPath.lastPathComponent;
        NSString *spinnerText = [NSString stringWithFormat:@"Installing %@", filename];

        if (totalFiles > 1) {
            printf("%s[%d/%d]%s %s%s%s\n", colBold(), (i - 1), totalFiles, colReset(), colCyan(), filename.UTF8String, colReset());
        }

        int status = runAsyncWithSpinner(spinnerText, 300.0, ^(void (^done)(int code)) {
            [[ContraXPCClient sharedClient] installIPA:canonicalPath completion:^(NSError * _Nullable error) {
                if (error) {
                    fprintf(stderr, "%s[-] Failed to install %s:%s %s (code %ld)\n",
                            colRed(),
                            filename.UTF8String,
                            colReset(),
                            error.localizedDescription.UTF8String ?: "Unknown error",
                            (long)error.code);
                    done(1);
                } else {
                    printf("%s[+] Successfully installed:%s %s\n",
                           colGreen(),
                           colReset(),
                           filename.UTF8String);
                    done(0);
                }
            }];
        });

        if (status == 0) {
            successCount++;
        } else {
            failureCount++;
        }
    }

    if (totalFiles > 1) {
        printf("\n%sSummary:%s %d succeeded, %d failed.\n",
               colBold(),
               colReset(),
               successCount,
               failureCount);
    }

    return (failureCount == 0) ? 0 : 1;
}

static int cmdUninstall(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "%s[-] Error:%s Missing bundle identifier.\n", colRed(), colReset());
        fprintf(stderr, "Usage: %s uninstall <bundle-id> [more-bundle-ids...]\n", argv[0]);
        return 1;
    }

    int total = argc - 2;
    int successCount = 0;
    int failureCount = 0;

    for (int i = 2; i < argc; i++) {
        NSString *bundleId = [NSString stringWithUTF8String:argv[i]];
        NSString *spinnerText = [NSString stringWithFormat:@"Uninstalling %@", bundleId];

        if (total > 1) {
            printf("%s[%d/%d]%s %s%s%s\n", colBold(), (i - 1), total, colReset(), colCyan(), bundleId.UTF8String, colReset());
        }

        int status = runAsyncWithSpinner(spinnerText, 60.0, ^(void (^done)(int code)) {
            [[ContraXPCClient sharedClient] uninstallAppWithBundleID:bundleId completion:^(NSError * _Nullable error) {
                if (error) {
                    fprintf(stderr, "%s[-] Failed to uninstall %s:%s %s\n",
                            colRed(),
                            bundleId.UTF8String,
                            colReset(),
                            error.localizedDescription.UTF8String ?: "Unknown error");
                    done(1);
                } else {
                    printf("%s[+] Successfully uninstalled:%s %s\n",
                           colGreen(),
                           colReset(),
                           bundleId.UTF8String);
                    done(0);
                }
            }];
        });

        if (status == 0) {
            successCount++;
        } else {
            failureCount++;
        }
    }

    if (total > 1) {
        printf("\n%sSummary:%s %d uninstalled, %d failed.\n",
               colBold(),
               colReset(),
               successCount,
               failureCount);
    }

    return (failureCount == 0) ? 0 : 1;
}

static int cmdList(void) {
    return runAsyncWithSpinner(@"Fetching installed applications...", 30.0, ^(void (^done)(int code)) {
        [[ContraXPCClient sharedClient] fetchAllInstalledAppsWithCompletion:^(NSArray<NSDictionary<NSString *,NSString *> *> * _Nullable apps) {
            if (!apps) {
                fprintf(stderr, "%s[-] Error:%s Failed to communicate with contrainstalld daemon.\n", colRed(), colReset());
                fprintf(stderr, "    Please verify that 'com.kurishu.contrainstalld' is active.\n");
                done(1);
                return;
            }

            if (apps.count == 0) {
                printf("%s[!] No applications installed via ContraStore.%s\n", colYellow(), colReset());
                done(0);
                return;
            }

            printf("%sInstalled Applications (%lu):%s\n", colBold(), (unsigned long)apps.count, colReset());
            printf("%s────────────────────────────────────────────────────────────%s\n", colGray(), colReset());

            NSUInteger idx = 1;
            for (NSDictionary<NSString *, NSString *> *app in apps) {
                NSString *bundleID = app[@"bundleID"] ?: @"(Unknown)";
                NSString *systemBundle = app[@"systemBundlePath"] ?: @"";
                NSString *systemData = app[@"systemDataPath"] ?: @"";
                NSString *fakeBundle = app[@"fakeBundlePath"] ?: @"";
                NSString *fakeData = app[@"fakeDataPath"] ?: @"";

                printf("%s[%lu]%s %s%s%s\n", colBold(), (unsigned long)idx++, colReset(), colCyan(), bundleID.UTF8String, colReset());
                if (systemBundle.length > 0) printf("    %sSystem Bundle:%s %s\n", colGray(), colReset(), systemBundle.UTF8String);
                if (systemData.length > 0)   printf("    %sSystem Data:  %s %s\n", colGray(), colReset(), systemData.UTF8String);
                if (fakeBundle.length > 0)   printf("    %sFake Bundle:  %s %s\n", colGray(), colReset(), fakeBundle.UTF8String);
                if (fakeData.length > 0)     printf("    %sFake Data:    %s %s\n", colGray(), colReset(), fakeData.UTF8String);
                printf("\n");
            }

            done(0);
        }];
    });
}

static int cmdInfo(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "%s[-] Error:%s Missing bundle identifier.\n", colRed(), colReset());
        fprintf(stderr, "Usage: %s info <bundle-id>\n", argv[0]);
        return 1;
    }

    NSString *bundleId = [NSString stringWithUTF8String:argv[2]];

    return runAsyncWithSpinner([NSString stringWithFormat:@"Querying info for %@...", bundleId], 15.0, ^(void (^done)(int code)) {
        [[ContraXPCClient sharedClient] fetchPathsForBundleID:bundleId completion:^(NSDictionary<NSString *,NSString *> * _Nullable info) {
            if (!info || info.count == 0) {
                fprintf(stderr, "%s[!] No record found for bundle identifier: '%s'%s\n",
                        colYellow(),
                        bundleId.UTF8String,
                        colReset());
                done(1);
                return;
            }

            printf("%sApplication Details:%s %s%s%s\n", colBold(), colReset(), colCyan(), bundleId.UTF8String, colReset());
            printf("%s────────────────────────────────────────────────────────────%s\n", colGray(), colReset());

            NSArray<NSString *> *orderedKeys = @[
                @"bundleID",
                @"systemBundlePath",
                @"systemDataPath",
                @"fakeBundlePath",
                @"fakeDataPath"
            ];

            for (NSString *key in orderedKeys) {
                NSString *value = info[key];
                if (value) {
                    printf("  %-18s: %s\n", key.UTF8String, value.UTF8String);
                }
            }

            for (NSString *key in info) {
                if (![orderedKeys containsObject:key]) {
                    printf("  %-18s: %s\n", key.UTF8String, info[key].UTF8String);
                }
            }

            done(0);
        }];
    });
}

static int cmdLogin(int argc, char *argv[]) {
    NSString *appleID = nil;
    BOOL isDebug = NO;

    for (int i = 2; i < argc; i++) {
        NSString *arg = [NSString stringWithUTF8String:argv[i]];
        if ([arg isEqualToString:@"--debug"] || [arg isEqualToString:@"-d"] || [arg isEqualToString:@"-v"] || [arg isEqualToString:@"--verbose"] || [arg isEqualToString:@"--debugv"] || [arg isEqualToString:@"debugv"]) {
            isDebug = YES;
        } else if (!appleID) {
            appleID = arg;
        }
    }

    if (!appleID || appleID.length == 0) {
        printf("  %s Apple ID: ", colCyan());
        fflush(stdout);
        char buf[256];
        if (fgets(buf, sizeof(buf), stdin) != NULL) {
            appleID = [[NSString stringWithUTF8String:buf] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        }
    }

    if (!appleID || appleID.length == 0) {
        fprintf(stderr, "%s[-] Error:%s Apple ID cannot be empty.\n", colRed(), colReset());
        return 1;
    }

    char *pass = getpass("  Enter Password: ");
    if (!pass || strlen(pass) == 0) {
        fprintf(stderr, "%s[-] Error:%s Password cannot be empty.\n", colRed(), colReset());
        return 1;
    }
    NSString *password = [NSString stringWithUTF8String:pass];

    if (isDebug) {
        printf("\n%s════════════════════════════════════════════════════════════════════════%s\n", colCyan(), colReset());
        printf("%s ContraStore Authentication Engine (Fortiva / GhostSign Core)%s\n", colBold(), colReset());
        printf(" Mode        : %sREALTIME DEBUG TRACE%s\n", colYellow(), colReset());
        printf(" Target User : %s%s%s\n", colCyan(), appleID.UTF8String, colReset());
        printf("%s════════════════════════════════════════════════════════════════════════%s\n\n", colCyan(), colReset());
        startRealtimeLogTailer();
    }

    __block BOOL needs2FA = NO;
    __block NSString *initialMsg = nil;

    int status = 0;
    if (isDebug) {
        status = runAsyncWithDirectWait(60.0, ^(void (^done)(int code)) {
            [[ContraXPCClient sharedClient] loginAppleID:appleID password:password completion:^(BOOL requires2FA, NSString * _Nullable message, NSError * _Nullable error) {
                if (error) {
                    fprintf(stderr, "\n%s[-] Authentication failed:%s %s\n",
                            colRed(), colReset(),
                            error.localizedDescription.UTF8String ?: "Unknown error");
                    done(1);
                    return;
                }
                if (requires2FA) {
                    needs2FA = YES;
                    initialMsg = message;
                    done(0);
                    return;
                }
                done(0);
            }];
        });
    } else {
        status = runAsyncWithSpinner(@"Authenticating with Apple ID (SRP-6a)...", 45.0, ^(void (^done)(int code)) {
            [[ContraXPCClient sharedClient] loginAppleID:appleID password:password completion:^(BOOL requires2FA, NSString * _Nullable message, NSError * _Nullable error) {
                if (error) {
                    fprintf(stderr, "%s[-] Authentication failed:%s %s\n",
                            colRed(), colReset(),
                            error.localizedDescription.UTF8String ?: "Unknown error");
                    done(1);
                    return;
                }
                if (requires2FA) {
                    needs2FA = YES;
                    initialMsg = message;
                    done(0);
                    return;
                }
                done(0);
            }];
        });
    }

    if (status != 0) {
        if (isDebug) stopRealtimeLogTailer();
        return status;
    }

    if (needs2FA) {
        printf("\n%s[!] Two-Factor Authentication required.%s\n", colYellow(), colReset());
        if (initialMsg.length > 0) {
            printf("%s[*] %s%s\n", colCyan(), initialMsg.UTF8String, colReset());
        } else {
            printf("%s[*] Verification code push has been triggered to your Apple devices.%s\n", colCyan(), colReset());
        }
        printf("%s[*] (Check your iPhone, iPad, or Mac for the Apple ID Verification Code)%s\n\n", colGray(), colReset());
        printf("  %sEnter 6-digit verification code:%s ", colBold(), colReset());
        fflush(stdout);

        char codeBuf[64];
        if (fgets(codeBuf, sizeof(codeBuf), stdin) == NULL) {
            if (isDebug) stopRealtimeLogTailer();
            fprintf(stderr, "%s[-] Failed to read verification code.%s\n", colRed(), colReset());
            return 1;
        }

        NSString *code = [[NSString stringWithUTF8String:codeBuf] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];

        int vStatus = 0;
        if (isDebug) {
            vStatus = runAsyncWithDirectWait(45.0, ^(void (^done)(int code)) {
                [[ContraXPCClient sharedClient] submit2FACode:code completion:^(BOOL success, NSString * _Nullable message, NSError * _Nullable error) {
                    if (!success || error) {
                        fprintf(stderr, "\n%s[-] 2FA validation failed:%s %s\n",
                                colRed(), colReset(),
                                error.localizedDescription.UTF8String ?: "Invalid verification code.");
                        done(1);
                    } else {
                        done(0);
                    }
                }];
            });
            stopRealtimeLogTailer();
        } else {
            vStatus = runAsyncWithSpinner(@"Validating verification code with Apple...", 45.0, ^(void (^done)(int code)) {
                [[ContraXPCClient sharedClient] submit2FACode:code completion:^(BOOL success, NSString * _Nullable message, NSError * _Nullable error) {
                    if (!success || error) {
                        fprintf(stderr, "%s[-] 2FA validation failed:%s %s\n",
                                colRed(), colReset(),
                                error.localizedDescription.UTF8String ?: "Invalid verification code.");
                        done(1);
                    } else {
                        done(0);
                    }
                }];
            });
        }

        if (vStatus != 0) return vStatus;
    } else {
        if (isDebug) stopRealtimeLogTailer();
    }

    // Fetch and display active Developer Account Card with Team ID
    runAsyncWithDirectWait(10.0, ^(void (^done)(int code)) {
        [[ContraXPCClient sharedClient] fetchAccountStatusWithCompletion:^(NSDictionary<NSString *,id> * _Nullable accountInfo, NSError * _Nullable error) {
            if (accountInfo) {
                printAccountSuccessCard(accountInfo);
            } else {
                printf("%s[+] Successfully authenticated as %s%s\n", colGreen(), appleID.UTF8String, colReset());
            }
            done(0);
        }];
    });

    return 0;
}

static int cmdLogout(void) {
    return runAsyncWithSpinner(@"Signing out...", 10.0, ^(void (^done)(int code)) {
        [[ContraXPCClient sharedClient] logoutWithCompletion:^(BOOL success, NSError * _Nullable error) {
            if (error) {
                fprintf(stderr, "%s[-] Logout error:%s %s\n", colRed(), colReset(), error.localizedDescription.UTF8String ?: "Unknown error");
                done(1);
            } else {
                printf("%s[+] Successfully signed out. Stored session removed.%s\n", colGreen(), colReset());
                done(0);
            }
        }];
    });
}

static int cmdAccount(void) {
    return runAsyncWithSpinner(@"Fetching Apple ID account status...", 15.0, ^(void (^done)(int code)) {
        [[ContraXPCClient sharedClient] fetchAccountStatusWithCompletion:^(NSDictionary<NSString *,id> * _Nullable accountInfo, NSError * _Nullable error) {
            if (error || !accountInfo) {
                printf("%s[!] Not currently logged in with Apple ID.%s\n", colYellow(), colReset());
                printf("    Run '%sct login <appleID>%s' to authenticate.\n", colCyan(), colReset());
                done(0);
                return;
            }

            printf("%sApple ID Account Status:%s\n", colBold(), colReset());
            printf("%s────────────────────────────────────────────────────────────%s\n", colGray(), colReset());
            NSString *appleID = accountInfo[@"appleID"] ?: @"(Unknown)";
            NSString *dsid = accountInfo[@"dsid"] ?: @"";
            NSString *teamName = accountInfo[@"teamName"] ?: @"";
            NSString *teamID = accountInfo[@"teamID"] ?: @"";
            NSString *expStr = accountInfo[@"expirationString"] ?: @"";
            BOOL isExpired = [accountInfo[@"isExpired"] boolValue];

            printf("  %-16s: %s%s%s\n", "Apple ID", colCyan(), appleID.UTF8String, colReset());
            if (dsid.length > 0) printf("  %-16s: %s\n", "DSID", dsid.UTF8String);
            if (teamName.length > 0) printf("  %-16s: %s\n", "Team Name", teamName.UTF8String);
            if (teamID.length > 0) printf("  %-16s: %s\n", "Team ID", teamID.UTF8String);
            if (expStr.length > 0) {
                if (isExpired) {
                    printf("  %-16s: %s%s (Expired)%s\n", "Session Status", colRed(), expStr.UTF8String, colReset());
                } else {
                    printf("  %-16s: %s%s (Active)%s\n", "Session Status", colGreen(), expStr.UTF8String, colReset());
                }
            }
            printf("\n");
            done(0);
        }];
    });
}

static int cmdAnisette(void) {
    return runAsyncWithSpinner(@"Querying on-device Anisette from akd daemon...", 15.0, ^(void (^done)(int code)) {
        [[ContraXPCClient sharedClient] testAnisetteWithCompletion:^(NSDictionary<NSString *,NSString *> * _Nullable headers, NSError * _Nullable error) {
            if (error || !headers) {
                fprintf(stderr, "%s[-] Failed to query Anisette:%s %s\n",
                        colRed(), colReset(),
                        error.localizedDescription.UTF8String ?: "akd daemon unreachable");
                done(1);
                return;
            }

            printf("%sOn-Device Anisette Attestation (AuthKit / akd):%s\n", colBold(), colReset());
            printf("%s────────────────────────────────────────────────────────────%s\n", colGray(), colReset());
            for (NSString *key in [headers.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
                printf("  %-24s: %s\n", key.UTF8String, headers[key].UTF8String);
            }
            printf("%s────────────────────────────────────────────────────────────%s\n", colGray(), colReset());
            printf("%s[+] Status: Local akd Anisette working on-device!%s\n\n", colGreen(), colReset());
            done(0);
        }];
    });
}

static int cmdSign(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "%s[-] Error:%s Missing IPA path to sign.\n", colRed(), colReset());
        fprintf(stderr, "Usage: %s sign <path.ipa> [-o output.ipa] [--adhoc]\n", argv[0]);
        return 1;
    }

    NSString *rawPath = [NSString stringWithUTF8String:argv[2]];
    NSString *expandedPath = [rawPath stringByExpandingTildeInPath];
    char resolvedBuffer[PATH_MAX];
    NSString *canonicalPath = nil;
    if (realpath(expandedPath.fileSystemRepresentation, resolvedBuffer) != NULL) {
        canonicalPath = [NSString stringWithUTF8String:resolvedBuffer];
    } else {
        canonicalPath = expandedPath.stringByStandardizingPath;
    }

    NSString *outputPath = nil;
    BOOL isAdhoc = NO;

    for (int i = 3; i < argc; i++) {
        NSString *arg = [NSString stringWithUTF8String:argv[i]];
        if ([arg isEqualToString:@"--adhoc"]) {
            isAdhoc = YES;
        } else if ([arg isEqualToString:@"-o"] || [arg isEqualToString:@"--output"]) {
            if (i + 1 < argc) {
                outputPath = [NSString stringWithUTF8String:argv[++i]];
            }
        }
    }

    NSString *filename = canonicalPath.lastPathComponent;
    NSString *spinnerText = [NSString stringWithFormat:@"Signing %@ with Native Engine...", filename];

    return runAsyncWithSpinner(spinnerText, 180.0, ^(void (^done)(int code)) {
        [[ContraXPCClient sharedClient] resignIPA:canonicalPath outputPath:outputPath adhoc:isAdhoc completion:^(NSString * _Nullable finalPath, NSError * _Nullable error) {
            if (error) {
                fprintf(stderr, "%s[-] Signing failed:%s %s\n", colRed(), colReset(), error.localizedDescription.UTF8String ?: "Unknown error");
                done(1);
            } else {
                printf("%s[+] Successfully signed:%s %s\n", colGreen(), colReset(), finalPath.UTF8String ?: canonicalPath.UTF8String);
                done(0);
            }
        }];
    });
}

#pragma mark - Main Entrypoint

int main(int argc, char *argv[]) {
    @autoreleasepool {
        gIsTTY = isatty(STDOUT_FILENO) && isatty(STDERR_FILENO);
        setupSignalHandlers();

        const char *progName = (argc > 0 && argv[0]) ? argv[0] : "ct";

        if (argc < 2) {
            printUsage(progName);
            return 0;
        }

        NSString *subcommand = [NSString stringWithUTF8String:argv[1]].lowercaseString;

        if ([subcommand isEqualToString:@"install"]) {
            return cmdInstall(argc, argv);
        } else if ([subcommand isEqualToString:@"uninstall"] || [subcommand isEqualToString:@"remove"] || [subcommand isEqualToString:@"rm"]) {
            return cmdUninstall(argc, argv);
        } else if ([subcommand isEqualToString:@"list"] || [subcommand isEqualToString:@"ls"]) {
            return cmdList();
        } else if ([subcommand isEqualToString:@"info"] || [subcommand isEqualToString:@"paths"]) {
            return cmdInfo(argc, argv);
        } else if ([subcommand isEqualToString:@"login"]) {
            return cmdLogin(argc, argv);
        } else if ([subcommand isEqualToString:@"logout"]) {
            return cmdLogout();
        } else if ([subcommand isEqualToString:@"whoami"] || [subcommand isEqualToString:@"account"] || [subcommand isEqualToString:@"status"]) {
            return cmdAccount();
        } else if ([subcommand isEqualToString:@"auth-log"] || [subcommand isEqualToString:@"log"]) {
            return cmdAuthLog();
        } else if ([subcommand isEqualToString:@"anisette"]) {
            return cmdAnisette();
        } else if ([subcommand isEqualToString:@"sign"]) {
            return cmdSign(argc, argv);
        } else if ([subcommand isEqualToString:@"version"] || [subcommand isEqualToString:@"-v"] || [subcommand isEqualToString:@"--version"]) {
            printVersion();
            return 0;
        } else if ([subcommand isEqualToString:@"help"] || [subcommand isEqualToString:@"-h"] || [subcommand isEqualToString:@"--help"]) {
            printUsage(progName);
            return 0;
        } else {
            fprintf(stderr, "%s[-] Unknown command:%s '%s'\n\n", colRed(), colReset(), argv[1]);
            printUsage(progName);
            return 1;
        }
    }
}
