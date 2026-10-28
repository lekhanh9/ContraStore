import Foundation

@objcMembers
final class ContraInstaller: NSObject, ContraInstallerProtocol {
    
    @objc enum InstallationError: Int, LocalizedError {
        case invalidSourceFile
        case payloadNotFound
        case appBundleNotFound
        case bundleIdentifierNotFound
        case resigningFailed
        case appNotInstalled
        
        var errorDescription: String? {
            switch self {
            case .invalidSourceFile:
                return "The provided IPA file is invalid or does not exist."
            case .payloadNotFound:
                return "Payload folder doesn't exist after unzipping."
            case .appBundleNotFound:
                return "App bundle (.app) doesn't exist."
            case .bundleIdentifierNotFound:
                return "App bundle identifier could not be found."
            case .resigningFailed:
                return "App bundle resigning failed" 
            case .appNotInstalled:
                return "The application is not installed."
            }
        }
    }
    
    //escape async hell
    private let installerQueue = DispatchQueue(label: "com.kurishu.contrainstalld.installerQueue", qos: .userInitiated)
    
    func installIpa(atPath path: String, withReply reply: @escaping (Error?) -> Void) {
        installerQueue.async {
            do {
                try self.performInstallation(atPath: path)
                reply(nil)
            } catch {
                reply(error)
            }
        }
    }

    func uninstallApp(withBundleId bundleId: String, withReply reply: @escaping (Error?) -> Void) {
        installerQueue.async {
            do {
                try self.performUninstallation(bundleId: bundleId)
                reply(nil)
            } catch {
                reply(error)
            }
        }
    }
    
    func getPathsForBundleId(_ bundleId: String, withReply reply: @escaping ([String : String]?) -> Void) {
        let info = DatabaseManager.shared.getAppInfo(forBundleID: bundleId)
        reply(info)
    }
    
    func getAllInstalledApps(reply: @escaping ([[String : String]]) -> Void) {
        let apps =  DatabaseManager.shared.getAllInstalledApps()
        reply(apps)
    } 
    
    func getAppIcon(forBundleId bundleId: String, withReply reply: @escaping (Data?) -> Void) {
        guard let info = DatabaseManager.shared.getAppInfo(forBundleID: bundleId),
        let bundlePath = info["systemBundlePath"] else { 
            reply(nil) 
            return
        }
        
        let res = getAppIconData(forPath: bundlePath)
        reply(res)
    }

    // MARK: - Apple ID & Authentication (GhostSign / Fortiva Engine)

    func loginAppleID(_ appleID: String, password: String, withReply reply: @escaping (Bool, String?, Error?) -> Void) {
        AppleSessionManager.shared.login(appleID: appleID, password: password) { requires2FA, message, error in
            reply(requires2FA, message, error)
        }
    }

    func submit2FACode(_ code: String, withReply reply: @escaping (Bool, String?, Error?) -> Void) {
        AppleSessionManager.shared.submit2FACode(code: code) { success, message, error in
            reply(success, message, error)
        }
    }

    func getAccountStatus(reply: @escaping ([String: Any]?, Error?) -> Void) {
        let status = AppleSessionManager.shared.getAccountStatus()
        reply(status, nil)
    }

    func logout(reply: @escaping (Bool, Error?) -> Void) {
        let success = AppleSessionManager.shared.logout()
        reply(success, nil)
    }

    func testAnisette(reply: @escaping ([String: String]?, Error?) -> Void) {
        do {
            let headers = try AppleSessionManager.shared.fetchLocalAnisette()
            reply(headers, nil)
        } catch {
            reply(nil, error)
        }
    }

    func resignIPA(atPath ipaPath: String, outputPath: String?, adhoc: Bool, withReply reply: @escaping (String?, Error?) -> Void) {
        installerQueue.async {
            do {
                let sourceURL = URL(fileURLWithPath: ipaPath).standardizedFileURL
                guard sourceURL.pathExtension.lowercased() == "ipa",
                      FileManager.default.fileExists(atPath: sourceURL.path) else {
                    throw InstallationError.invalidSourceFile
                }

                let stagedDirURL = try self.createStagingDirectory(for: sourceURL)
                defer { self.cleanupDirectory(at: stagedDirURL) }

                try self.stageAndExtractIPA(from: sourceURL, to: stagedDirURL)
                let stagedAppURL = try self.locateAppBundle(in: stagedDirURL)

                try self.resignStagedApp(at: stagedAppURL)

                let destinationURL: URL
                if let out = outputPath, !out.isEmpty {
                    destinationURL = URL(fileURLWithPath: out).standardizedFileURL
                } else {
                    let parent = sourceURL.deletingLastPathComponent()
                    let baseName = sourceURL.deletingPathExtension().lastPathComponent
                    destinationURL = parent.appendingPathComponent("\(baseName)-resigned.ipa")
                }

                if FileManager.default.fileExists(atPath: destinationURL.path) {
                    try? FileManager.default.removeItem(at: destinationURL)
                }

                // Repack payload using posix_spawn zip or fallback copy
                let payloadURL = stagedDirURL.appendingPathComponent("Payload")
                if FileManager.default.fileExists(atPath: payloadURL.path) {
                    do {
                        try AppResigner.repackPayload(atDirectory: stagedDirURL.path, toIPA: destinationURL.path)
                    } catch {
                        try FileManager.default.copyItem(at: sourceURL, to: destinationURL)
                    }
                }

                reply(destinationURL.path, nil)
            } catch {
                reply(nil, error)
            }
        }
    } 
        
        
        
    
    private func performInstallation(atPath path: String) throws {
        let sourceURL = URL(fileURLWithPath: path).standardizedFileURL
        
        guard sourceURL.pathExtension.lowercased() == "ipa",
              FileManager.default.fileExists(atPath: sourceURL.path) else {
            throw InstallationError.invalidSourceFile
        }
        
        let stagedDirURL = try createStagingDirectory(for: sourceURL)
        defer { cleanupDirectory(at: stagedDirURL) }
        
        try stageAndExtractIPA(from: sourceURL, to: stagedDirURL)
        
        let stagedAppURL = try locateAppBundle(in: stagedDirURL)
        let bundleID = try extractBundleIdentifier(from: stagedAppURL)
        
        try resignStagedApp(at: stagedAppURL)
        
        let existingAppInfo = DatabaseManager.shared.getAppInfo(forBundleID: bundleID)
        let installedAppURL = try installAppBundle(from: stagedAppURL, bundleID: bundleID, existingInfo: existingAppInfo) 
        
        let appInfo = try registerOrUpdateAppInDatabase(bundleID: bundleID, installedAppURL: installedAppURL, existingInfo: existingAppInfo)
        
        try createStandardAppDirectories(with: appInfo)
        
        refreshIconCache(for: installedAppURL)
    }

    private func performUninstallation(bundleId: String) throws {
        guard let appInfo = DatabaseManager.shared.getAppInfo(forBundleID: bundleId) else {
            throw InstallationError.appNotInstalled
        }

        let fileManager = FileManager.default

        if let systemBundlePath = appInfo["systemBundlePath"] {
            systemBundlePath.withCString { path in
                uicache_unregister(path)
            }
            if fileManager.fileExists(atPath: systemBundlePath) {
                try? fileManager.removeItem(atPath: systemBundlePath)
            }
        }

        if let systemDataPath = appInfo["systemDataPath"], fileManager.fileExists(atPath: systemDataPath) {
            try? fileManager.removeItem(atPath: systemDataPath)
        }

        DatabaseManager.shared.deleteApp(bundleID: bundleId)
    }
    
    
}
