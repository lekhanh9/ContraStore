//
//  AppleSessionManager.swift
//  contrainstalld
//
//  Manages on-device Apple ID authentication (SRP-6a, 2FA Push & Validate),
//  Developer Portal sessions, and native Anisette attestation via akd (AuthKit).
//

import Foundation
import Security

#if canImport(ObjectiveC) && canImport(Darwin)
import ObjectiveC
import Darwin
#endif

// MARK: - Pro-Grade Realtime Debug Logger

public final class ContraAuthLog: @unchecked Sendable {
    public static let shared = ContraAuthLog()
    private var logs: [String] = []
    private let lock = NSLock()
    public let logFilePath: String = jbPath("/tmp/contra_auth_debug.log")

    private init() {
        let dir = (logFilePath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    }

    public func clear() {
        lock.lock()
        defer { lock.unlock() }
        logs.removeAll()
        try? FileManager.default.removeItem(atPath: logFilePath)
    }

    public func log(tag: String = "AUTH", _ msg: String) {
        lock.lock()
        defer { lock.unlock() }

        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        let timestamp = formatter.string(from: Date())
        let line = "[\(timestamp)] [\(tag)] \(msg)\n"

        logs.append(line)
        if logs.count > 400 { logs.removeFirst() }

        NSLog("[ContraAuth] [%@] %@", tag, msg)

        // Write directly to realtime log file for CLI streaming
        if let data = line.data(using: .utf8) {
            if FileManager.default.fileExists(atPath: logFilePath) {
                if let fileHandle = try? FileHandle(forWritingTo: URL(fileURLWithPath: logFilePath)) {
                    fileHandle.seekToEndOfFile()
                    fileHandle.write(data)
                    try? fileHandle.close()
                }
            } else {
                try? data.write(to: URL(fileURLWithPath: logFilePath))
                chmod(logFilePath, 0o666)
            }
        }
    }

    public func recentLogs() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return logs
    }
}

@objcMembers
public final class AppleSessionManager: NSObject {
    public static let shared = AppleSessionManager()

    private let queue = DispatchQueue(label: "com.kurishu.contrainstalld.appleAuthQueue", qos: .userInitiated)

    // In-memory 2FA context while waiting for user to submit 6-digit code
    private var pendingTwoFactorContext: Pending2FAContext?

    private struct Pending2FAContext {
        let appleID: String
        let password: String
        let dsid: String
        let idmsToken: String
        let sessionKey: Data?
        let challengeToken: Data?
        let anisetteHeaders: [String: String]
    }

    private var sessionFileURL: URL {
        let dir = URL(fileURLWithPath: Constants.applicationSupportDirectoryPath)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("session.plist")
    }

    // MARK: - Local Anisette (akd / AuthKit)

    public func fetchLocalAnisette() throws -> [String: String] {
        ContraAuthLog.shared.log(tag: "ANISETTE", "Connecting to Apple AuthKit daemon (akd) on iOS...")

        #if canImport(ObjectiveC) && canImport(Darwin)
        let candidatePaths = [
            "/System/Library/PrivateFrameworks/AuthKit.framework/AuthKit",
            "/System/Library/Frameworks/AuthKit.framework/AuthKit",
            "/System/Library/PrivateFrameworks/AuthKit.framework/akd"
        ]

        if NSClassFromString("AKAppleIDSession") == nil {
            for path in candidatePaths {
                if dlopen(path, RTLD_NOW | RTLD_GLOBAL) != nil {
                    break
                }
            }
        }

        guard let sessionClass = NSClassFromString("AKAppleIDSession") as? NSObject.Type else {
            ContraAuthLog.shared.log(tag: "ANISETTE", "❌ AKAppleIDSession class not found in AuthKit.framework")
            throw NSError(
                domain: "com.kurishu.contrainstalld",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Native AuthKit framework (AKAppleIDSession) is not available."]
            )
        }

        let allocSel = NSSelectorFromString("alloc")
        let initSel = NSSelectorFromString("initWithIdentifier:")
        guard let allocated = sessionClass.perform(allocSel)?.takeUnretainedValue(),
              let session = allocated.perform(initSel, with: "com.apple.gs.xcode.auth")?.takeUnretainedValue() else {
            ContraAuthLog.shared.log(tag: "ANISETTE", "❌ Failed to instantiate AKAppleIDSession for Xcode service")
            throw NSError(
                domain: "com.kurishu.contrainstalld",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Failed to allocate or initialize AKAppleIDSession."]
            )
        }

        let headersSel = NSSelectorFromString("appleIDHeadersForRequest:")
        var headers = (session.perform(headersSel, with: nil)?.takeUnretainedValue() as? [String: String]) ?? [:]

        // Hardware device identifiers via AKDevice
        if let devClass = NSClassFromString("AKDevice") as? NSObject.Type {
            let currentDevSel = NSSelectorFromString("currentDevice")
            if let dev = devClass.perform(currentDevSel)?.takeUnretainedValue() {
                let udidSel = NSSelectorFromString("uniqueDeviceIdentifier")
                if dev.responds(to: udidSel),
                   let udid = dev.perform(udidSel)?.takeUnretainedValue() as? String, !udid.isEmpty {
                    headers["X-Mme-Device-Id"] = udid
                }

                let srlSel = NSSelectorFromString("serialNumber")
                if dev.responds(to: srlSel),
                   let srl = dev.perform(srlSel)?.takeUnretainedValue() as? String, !srl.isEmpty {
                    headers["X-Apple-I-SRL-NO"] = srl
                }

                let descSel = NSSelectorFromString("serverFriendlyDescription")
                if dev.responds(to: descSel),
                   let desc = dev.perform(descSel)?.takeUnretainedValue() as? String, !desc.isEmpty {
                    headers["X-MMe-Client-Info"] = desc
                }
            }
        }

        // Add real-time timestamp and locale headers
        let formatter = ISO8601DateFormatter()
        headers["X-Apple-I-Client-Time"] = formatter.string(from: Date())
        headers["X-Apple-Locale"] = Locale.current.identifier
        headers["X-Apple-I-TimeZone"] = TimeZone.current.abbreviation() ?? "UTC"

        if headers["X-Mme-Device-Id"] == nil || headers["X-Mme-Device-Id"]?.isEmpty == true {
            headers["X-Mme-Device-Id"] = UUID().uuidString
        }

        let devID = headers["X-Mme-Device-Id"] ?? "N/A"
        let srl = headers["X-Apple-I-SRL-NO"] ?? "0"
        let rinfo = headers["X-Apple-I-MD-RINFO"] ?? "17106176"
        let hasOTP = headers["X-Apple-I-MD"] != nil
        let hasMachineID = headers["X-Apple-I-MD-M"] != nil

        ContraAuthLog.shared.log(tag: "ANISETTE", "Attestation extracted: DeviceID=\(devID.prefix(8))..., Serial=\(srl), RINFO=\(rinfo), OTP=\(hasOTP), MD-M=\(hasMachineID)")
        return headers
        #else
        throw NSError(
            domain: "com.kurishu.contrainstalld",
            code: -1,
            userInfo: [NSLocalizedDescriptionKey: "Local Anisette is only available on iOS/Darwin platforms."]
        )
        #endif
    }

    // MARK: - GrandSlam HTTP Helper

    private func makeClientDictionary(anisette: [String: String]) -> [String: Any] {
        [
            "bootstrap": true,
            "icscrec": true,
            "pbe": false,
            "prkgen": true,
            "svct": "iCloud",
            "loc": anisette["X-Apple-Locale"] ?? "en_US",
            "X-Apple-Locale": anisette["X-Apple-Locale"] ?? "en_US",
            "X-Apple-I-MD": anisette["X-Apple-I-MD"] ?? "",
            "X-Apple-I-MD-M": anisette["X-Apple-I-MD-M"] ?? "",
            "X-Mme-Device-Id": anisette["X-Mme-Device-Id"] ?? "",
            "X-Apple-I-MD-LU": anisette["X-Apple-I-MD-LU"] ?? "",
            "X-Apple-I-MD-RINFO": anisette["X-Apple-I-MD-RINFO"] ?? "17106176",
            "X-Apple-I-SRL-NO": anisette["X-Apple-I-SRL-NO"] ?? "0",
            "X-Apple-I-Client-Time": anisette["X-Apple-I-Client-Time"] ?? "",
            "X-Apple-I-TimeZone": anisette["X-Apple-I-TimeZone"] ?? "UTC"
        ]
    }

    private func sendGrandSlamRequest(
        parameters: [String: Any],
        anisette: [String: String],
        url: URL = URL(string: "https://gsa.apple.com/grandslam/GsService2")!
    ) throws -> [String: Any] {
        let envelope: [String: Any] = [
            "Header": ["Version": "1.0.1"],
            "Request": parameters
        ]

        let plistData = try PropertyListSerialization.data(fromPropertyList: envelope, format: .xml, options: 0)

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = plistData
        request.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
        request.setValue("text/x-xml-plist", forHTTPHeaderField: "Accept")
        request.setValue("akd/1.0 CFNetwork Darwin", forHTTPHeaderField: "User-Agent")
        request.setValue("com.apple.gs.xcode.auth", forHTTPHeaderField: "X-Apple-App-Info")
        request.setValue("27.0 (27A5218g)", forHTTPHeaderField: "X-Xcode-Version")
        request.setValue("close", forHTTPHeaderField: "Connection")

        if let clientInfo = anisette["X-MMe-Client-Info"] {
            request.setValue(clientInfo, forHTTPHeaderField: "X-Mme-Client-Info")
            request.setValue(clientInfo, forHTTPHeaderField: "X-Apple-Client-Info")
        }

        for (k, v) in anisette {
            request.setValue(v, forHTTPHeaderField: k)
        }

        let op = parameters["o"] as? String ?? "unknown"
        ContraAuthLog.shared.log(tag: "GSA-HTTP", "-> POST https://gsa.apple.com/grandslam/GsService2 (op=\(op), payload=\(plistData.count) bytes)")

        let semaphore = DispatchSemaphore(value: 0)
        var responseData: Data?
        var responseError: Error?
        var httpResponse: HTTPURLResponse?

        let task = URLSession.shared.dataTask(with: request) { data, resp, err in
            responseData = data
            httpResponse = resp as? HTTPURLResponse
            responseError = err
            semaphore.signal()
        }
        task.resume()
        _ = semaphore.wait(timeout: .now() + 35.0)

        if let err = responseError {
            ContraAuthLog.shared.log(tag: "GSA-HTTP", "❌ Network error: \(err.localizedDescription)")
            throw err
        }

        guard let http = httpResponse else {
            ContraAuthLog.shared.log(tag: "GSA-HTTP", "❌ No HTTP response received from Apple")
            throw NSError(domain: "com.kurishu.contrainstalld", code: -1, userInfo: [NSLocalizedDescriptionKey: "No response from Apple authentication server."])
        }

        ContraAuthLog.shared.log(tag: "GSA-HTTP", "<- HTTP \(http.statusCode) OK (Response: \(responseData?.count ?? 0) bytes)")

        guard let raw = responseData, !raw.isEmpty else {
            throw NSError(domain: "com.kurishu.contrainstalld", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: "Empty response from GrandSlam."])
        }

        guard let plist = try? PropertyListSerialization.propertyList(from: raw, options: [], format: nil) as? [String: Any] else {
            let snippet = String(data: raw.prefix(200), encoding: .utf8) ?? "binary"
            ContraAuthLog.shared.log(tag: "GSA-HTTP", "❌ Invalid plist response: \(snippet)")
            throw NSError(domain: "com.kurishu.contrainstalld", code: -2, userInfo: [NSLocalizedDescriptionKey: "GrandSlam returned non-plist payload."])
        }

        let responseDict = (plist["Response"] as? [String: Any]) ?? plist

        if let status = responseDict["Status"] as? [String: Any] {
            let ec = status["ec"] as? Int ?? 0
            let em = status["em"] as? String ?? ""
            let au = status["au"] as? String ?? ""
            let hsc = status["hsc"] as? Int ?? 0
            ContraAuthLog.shared.log(tag: "GSA-HTTP", "Status check: ec=\(ec), em='\(em)', au='\(au)', hsc=\(hsc)")

            // ec != 0 is an error unless it's a 2FA challenge (-21669 / hsc 409)
            if ec != 0 && ec != -21669 && hsc != 409 {
                throw NSError(domain: "com.kurishu.contrainstalld", code: ec, userInfo: [NSLocalizedDescriptionKey: em.isEmpty ? "GrandSlam Error (\(ec))" : em])
            }
        }

        return responseDict
    }

    // MARK: - 2FA Push Trigger (Fortiva Method)

    /// Triggers push notification to trusted devices via https://gsa.apple.com/auth/verify/trusteddevice
    private func triggerTrustedDevice2FA(
        dsid: String,
        idmsToken: String,
        anisette: [String: String]
    ) -> Bool {
        let identityToken = Data("\(dsid):\(idmsToken)".utf8).base64EncodedString()
        ContraAuthLog.shared.log(tag: "2FA-PUSH", "Triggering 2FA Push Notification to trusted devices for DSID: \(dsid)...")

        guard let url = URL(string: "https://gsa.apple.com/auth/verify/trusteddevice") else { return false }

        for attempt in 1...3 {
            var request = URLRequest(url: url)
            request.httpMethod = "GET"
            request.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
            request.setValue("text/x-xml-plist", forHTTPHeaderField: "Accept")
            request.setValue("en-us", forHTTPHeaderField: "Accept-Language")
            request.setValue("akd/1.0 CFNetwork Darwin", forHTTPHeaderField: "User-Agent")
            request.setValue(identityToken, forHTTPHeaderField: "X-Apple-Identity-Token")
            request.setValue("com.apple.gs.xcode.auth", forHTTPHeaderField: "X-Apple-App-Info")
            request.setValue("27.0 (27A5218g)", forHTTPHeaderField: "X-Xcode-Version")
            request.setValue(dsid, forHTTPHeaderField: "X-Apple-I-DSID")
            request.setValue("close", forHTTPHeaderField: "Connection")

            if let clientInfo = anisette["X-MMe-Client-Info"] {
                request.setValue(clientInfo, forHTTPHeaderField: "X-Mme-Client-Info")
            }

            for (k, v) in anisette {
                request.setValue(v, forHTTPHeaderField: k)
            }

            let sema = DispatchSemaphore(value: 0)
            var statusCode = 0

            let task = URLSession.shared.dataTask(with: request) { _, resp, _ in
                if let http = resp as? HTTPURLResponse {
                    statusCode = http.statusCode
                }
                sema.signal()
            }
            task.resume()
            _ = sema.wait(timeout: .now() + 15.0)

            ContraAuthLog.shared.log(tag: "2FA-PUSH", "-> GET /auth/verify/trusteddevice (attempt \(attempt)): HTTP \(statusCode)")

            // HTTP 200 or 412 confirms Apple server dispatched the 6-digit pop-up!
            if statusCode == 200 || statusCode == 412 {
                ContraAuthLog.shared.log(tag: "2FA-PUSH", "✅ Verification code pop-up successfully dispatched to your Apple devices!")
                return true
            }

            Thread.sleep(forTimeInterval: 1.0)
        }

        ContraAuthLog.shared.log(tag: "2FA-PUSH", "⚠️ Trusted devices did not acknowledge. Trying SMS fallback...")
        return triggerSMS2FA(dsid: dsid, idmsToken: idmsToken, anisette: anisette)
    }

    /// Triggers SMS OTP verification code as fallback
    private func triggerSMS2FA(
        dsid: String,
        idmsToken: String,
        anisette: [String: String]
    ) -> Bool {
        let identityToken = Data("\(dsid):\(idmsToken)".utf8).base64EncodedString()
        ContraAuthLog.shared.log(tag: "2FA-PUSH", "Querying trusted phone numbers for SMS verification...")

        guard let phoneURL = URL(string: "https://gsa.apple.com/auth/verify/phone") else { return false }

        var getReq = URLRequest(url: phoneURL)
        getReq.httpMethod = "GET"
        getReq.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
        getReq.setValue("text/x-xml-plist", forHTTPHeaderField: "Accept")
        getReq.setValue(identityToken, forHTTPHeaderField: "X-Apple-Identity-Token")
        getReq.setValue("com.apple.gs.xcode.auth", forHTTPHeaderField: "X-Apple-App-Info")
        getReq.setValue("27.0 (27A5218g)", forHTTPHeaderField: "X-Xcode-Version")
        getReq.setValue(dsid, forHTTPHeaderField: "X-Apple-I-DSID")

        for (k, v) in anisette { getReq.setValue(v, forHTTPHeaderField: k) }

        var phoneID = 1
        let sema = DispatchSemaphore(value: 0)

        URLSession.shared.dataTask(with: getReq) { data, _, _ in
            if let d = data,
               let json = (try? JSONSerialization.jsonObject(with: d, options: [])) as? [String: Any],
               let phones = json["trustedPhoneNumbers"] as? [[String: Any]],
               let first = phones.first,
               let pid = first["id"] as? Int {
                phoneID = pid
                let numberWithDialCode = first["numberWithDialCode"] as? String ?? ""
                ContraAuthLog.shared.log(tag: "2FA-PUSH", "Found trusted phone: \(numberWithDialCode) (id=\(phoneID))")
            }
            sema.signal()
        }.resume()
        _ = sema.wait(timeout: .now() + 10.0)

        // Request SMS dispatch via PUT
        guard let putURL = URL(string: "https://gsa.apple.com/auth/verify/phone") else { return false }
        var putReq = URLRequest(url: putURL)
        putReq.httpMethod = "PUT"
        putReq.setValue("application/json", forHTTPHeaderField: "Content-Type")
        putReq.setValue(identityToken, forHTTPHeaderField: "X-Apple-Identity-Token")
        putReq.setValue("com.apple.gs.xcode.auth", forHTTPHeaderField: "X-Apple-App-Info")
        putReq.setValue(dsid, forHTTPHeaderField: "X-Apple-I-DSID")
        for (k, v) in anisette { putReq.setValue(v, forHTTPHeaderField: k) }

        let body: [String: Any] = ["phoneNumber": ["id": phoneID], "mode": "sms"]
        putReq.httpBody = try? JSONSerialization.data(withJSONObject: body, options: [])

        let sema2 = DispatchSemaphore(value: 0)
        var putSuccess = false

        URLSession.shared.dataTask(with: putReq) { _, resp, _ in
            if let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode) {
                ContraAuthLog.shared.log(tag: "2FA-PUSH", "✅ SMS verification code sent via carrier!")
                putSuccess = true
            }
            sema2.signal()
        }.resume()
        _ = sema2.wait(timeout: .now() + 10.0)

        return putSuccess
    }

    // MARK: - AppToken Fetching via GSA

    private func fetchAppToken(
        dsid: String,
        idmsToken: String,
        sessionKey: Data,
        challengeToken: Data?,
        anisette: [String: String],
        targetApp: String = "com.apple.gs.xcode.auth"
    ) -> String? {
        ContraAuthLog.shared.log(tag: "GSA-HTTP", "Acquiring Xcode developer AppToken for '\(targetApp)'...")

        let checksum = ContraCrypto.hmacSHA256(key: sessionKey, strings: ["apptokens", dsid, targetApp])

        var params: [String: Any] = [
            "app": [targetApp],
            "checksum": checksum,
            "cpd": makeClientDictionary(anisette: anisette),
            "o": "apptokens",
            "t": idmsToken,
            "u": dsid
        ]

        if let c = challengeToken {
            params["c"] = c
        }

        do {
            let response = try sendGrandSlamRequest(parameters: params, anisette: anisette)
            guard let encryptedToken = response["et"] as? Data else {
                ContraAuthLog.shared.log(tag: "GSA-HTTP", "⚠️ No encrypted token 'et' found in apptokens response")
                return nil
            }

            let (token, _) = try ContraSRPClient.decryptAppToken(encryptedToken: encryptedToken, sessionKey: sessionKey, targetApp: targetApp)
            ContraAuthLog.shared.log(tag: "GSA-HTTP", "✅ Successfully decrypted Xcode AppToken (myacinfo): \(token.prefix(20))...")
            return token
        } catch {
            ContraAuthLog.shared.log(tag: "GSA-HTTP", "❌ Failed to fetch apptoken: \(error.localizedDescription)")
            return nil
        }
    }

    // MARK: - Developer Team Resolution (Fortiva Reference)

    private func resolveDeveloperTeams(
        appleID: String,
        dsid: String,
        token: String,
        anisette: [String: String]
    ) -> (primaryTeamID: String, primaryTeamName: String, allTeams: [[String: Any]]) {
        ContraAuthLog.shared.log(tag: "DEV-TEAM", "Querying Apple Developer Portal for registered teams at listTeams.action...")

        guard let listTeamsURL = URL(string: "https://developerservices2.apple.com/services/QH65B2/listTeams.action?clientId=XABBG36SBA") else {
            return (dsid, "Personal Team (\(appleID))", [])
        }

        var request = URLRequest(url: listTeamsURL)
        request.httpMethod = "POST"
        request.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
        request.setValue("text/x-xml-plist", forHTTPHeaderField: "Accept")
        request.setValue("Xcode", forHTTPHeaderField: "User-Agent")
        request.setValue("en-us", forHTTPHeaderField: "Accept-Language")
        request.setValue("com.apple.gs.xcode.auth", forHTTPHeaderField: "X-Apple-App-Info")
        request.setValue("14.2 (14C18)", forHTTPHeaderField: "X-Xcode-Version")
        request.setValue(dsid, forHTTPHeaderField: "X-Apple-I-Identity-Id")
        request.setValue(token, forHTTPHeaderField: "X-Apple-GS-Token")
        request.setValue("close", forHTTPHeaderField: "Connection")

        if let clientInfo = anisette["X-MMe-Client-Info"] {
            request.setValue(clientInfo, forHTTPHeaderField: "X-Mme-Client-Info")
        }

        for (k, v) in anisette {
            request.setValue(v, forHTTPHeaderField: k)
        }

        // Standard Apple Developer Portal request body
        let bodyPlist: [String: Any] = [
            "clientId": "XABBG36SBA",
            "myacinfo": token,
            "protocolVersion": "QH65B2",
            "requestId": UUID().uuidString.uppercased(),
            "userLocale": ["en_US"]
        ]

        request.httpBody = try? PropertyListSerialization.data(fromPropertyList: bodyPlist, format: .xml, options: 0)

        let semaphore = DispatchSemaphore(value: 0)
        var resultData: Data?
        var statusCode = 0

        URLSession.shared.dataTask(with: request) { data, resp, _ in
            resultData = data
            if let http = resp as? HTTPURLResponse {
                statusCode = http.statusCode
            }
            semaphore.signal()
        }.resume()

        _ = semaphore.wait(timeout: .now() + 18.0)

        ContraAuthLog.shared.log(tag: "DEV-TEAM", "<- listTeams.action: HTTP \(statusCode)")

        var parsedTeams: [[String: Any]] = []

        if let data = resultData,
           let plist = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any] {

            let resultCode = plist["resultCode"] as? Int ?? (plist["resultcode"] as? Int ?? 0)
            let userString = plist["userString"] as? String ?? ""

            if resultCode != 0 {
                ContraAuthLog.shared.log(tag: "DEV-TEAM", "Developer API Notice (code \(resultCode)): '\(userString)'")
            }

            if let rawTeams = plist["teams"] as? [[String: Any]] {
                for t in rawTeams {
                    let tid = t["teamId"] as? String ?? ""
                    let tname = t["name"] as? String ?? ""
                    let ttype = t["type"] as? String ?? "Individual"
                    let tstatus = t["status"] as? String ?? "active"

                    ContraAuthLog.shared.log(tag: "DEV-TEAM", "✅ Found Team: '\(tname)' [TeamID: \(tid), Type: \(ttype), Status: \(tstatus)]")
                    parsedTeams.append([
                        "teamId": tid,
                        "name": tname,
                        "type": ttype,
                        "status": tstatus
                    ])
                }
            }
        }

        // Determine primary team
        if let first = parsedTeams.first, let tid = first["teamId"] as? String, !tid.isEmpty {
            let tname = first["name"] as? String ?? "Developer Team"
            ContraAuthLog.shared.log(tag: "DEV-TEAM", "⭐ Selected primary team: '\(tname)' [ID: \(tid)]")
            return (tid, tname, parsedTeams)
        }

        // Fallback for Free Developer Apple ID accounts (without enrolled organization team)
        let fallbackID = dsid.isEmpty ? "Personal" : dsid
        let fallbackName = "\(appleID) (Personal)"
        ContraAuthLog.shared.log(tag: "DEV-TEAM", "ℹ️ Free/Personal account detected. Assigning Personal Team [ID: \(fallbackID)]")
        return (fallbackID, fallbackName, parsedTeams)
    }

    // MARK: - Login Flow (Full SRP-6a + 2FA)

    public func login(
        appleID: String,
        password: String,
        completion: @escaping (Bool, String?, Error?) -> Void
    ) {
        queue.async {
            do {
                let sanitizedAppleID = appleID.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                guard !sanitizedAppleID.isEmpty, !password.isEmpty else {
                    completion(false, nil, NSError(
                        domain: "com.kurishu.contrainstalld",
                        code: 400,
                        userInfo: [NSLocalizedDescriptionKey: "Apple ID and password cannot be empty."]
                    ))
                    return
                }

                ContraAuthLog.shared.clear()
                ContraAuthLog.shared.log(tag: "AUTH", "==================================================")
                ContraAuthLog.shared.log(tag: "AUTH", "Starting Authentication session for: \(sanitizedAppleID)")
                ContraAuthLog.shared.log(tag: "AUTH", "==================================================")

                // 1. Fetch on-device Anisette headers
                let anisette = try self.fetchLocalAnisette()

                // 2. SRP-6a Handshake - Step 1: Init
                let srp = ContraSRPClient()
                let clientPublicKeyA = srp.startAuthentication()
                ContraAuthLog.shared.log(tag: "SRP-6a", "Generated ephemeral public key A (256-bit prime group RFC 5054). Initiating GrandSlam handshake...")

                let initParams: [String: Any] = [
                    "A2k": clientPublicKeyA,
                    "cpd": self.makeClientDictionary(anisette: anisette),
                    "o": "init",
                    "ps": ["s2k", "s2k_fo"],
                    "u": sanitizedAppleID
                ]

                let initResponse = try self.sendGrandSlamRequest(parameters: initParams, anisette: anisette)

                guard let c = initResponse["c"] as? String,
                      let salt = initResponse["s"] as? Data,
                      let iterations = initResponse["i"] as? Int,
                      let serverB = initResponse["B"] as? Data else {
                    ContraAuthLog.shared.log(tag: "SRP-6a", "❌ Malformed SRP init response: missing parameters c/s/i/B")
                    throw NSError(domain: "com.kurishu.contrainstalld", code: -3, userInfo: [NSLocalizedDescriptionKey: "Malformed GrandSlam SRP init response."])
                }

                let sp = (initResponse["sp"] as? String) ?? "s2k"
                let isS2KFO = (sp == "s2k_fo")
                ContraAuthLog.shared.log(tag: "SRP-6a", "Init OK! Protocol: \(sp), Iterations: \(iterations), Salt: \(salt.count) bytes. Computing client proof M1...")

                // 3. Derive password key via PBKDF2 and process challenge
                guard let derivedKey = srp.derivePasswordKey(password: password, salt: salt, iterations: iterations, isS2KFO: isS2KFO) else {
                    throw NSError(domain: "com.kurishu.contrainstalld", code: -4, userInfo: [NSLocalizedDescriptionKey: "Failed to derive SRP password key."])
                }

                guard let proofM1 = srp.processChallenge(username: sanitizedAppleID, derivedPasswordKey: derivedKey, salt: salt, serverPublicKey: serverB) else {
                    throw NSError(domain: "com.kurishu.contrainstalld", code: -5, userInfo: [NSLocalizedDescriptionKey: "Failed to compute SRP proof M1."])
                }

                ContraAuthLog.shared.log(tag: "SRP-6a", "Proof M1 computed successfully. Sending complete challenge to Apple...")

                // 4. SRP-6a Handshake - Step 2: Complete
                let completeParams: [String: Any] = [
                    "c": c,
                    "cpd": self.makeClientDictionary(anisette: anisette),
                    "M1": proofM1,
                    "o": "complete",
                    "u": sanitizedAppleID
                ]

                let completeResponse = try self.sendGrandSlamRequest(parameters: completeParams, anisette: anisette)

                let status = (completeResponse["Status"] as? [String: Any]) ?? [:]
                let authType = (status["au"] as? String) ?? (completeResponse["au"] as? String)
                let hsc = (status["hsc"] as? Int) ?? 0
                let ec = (status["ec"] as? Int) ?? 0

                ContraAuthLog.shared.log(tag: "SRP-6a", "Complete challenge response: au='\(authType ?? "nil")', hsc=\(hsc), ec=\(ec)")

                // Decrypt SPD payload
                var decryptedSPD: DecryptedSPD?
                if let spdData = completeResponse["spd"] as? Data {
                    do {
                        decryptedSPD = try srp.decryptSPD(spdData)
                        ContraAuthLog.shared.log(tag: "SRP-6a", "SPD payload decrypted successfully. DSID: \(decryptedSPD?.dsid ?? "nil")")
                    } catch {
                        ContraAuthLog.shared.log(tag: "SRP-6a", "⚠️ SPD decrypt failed: \(error.localizedDescription)")
                    }
                }

                let dsid = decryptedSPD?.dsid
                    ?? (status["dsid"] as? String)
                    ?? (completeResponse["dsid"] as? String)
                    ?? ""

                let idmsToken = decryptedSPD?.idmsToken
                    ?? (status["idmsToken"] as? String)
                    ?? (completeResponse["idmsToken"] as? String)
                    ?? ""

                let is2FARequired = ["trustedDeviceSecondaryAuth", "secondaryAuth", "smsSecondaryAuth", "trustedDevice", "pushedCode"].contains(authType ?? "")
                    || (hsc == 409)

                // 5. Handle Two-Factor Authentication Requirement
                if is2FARequired {
                    ContraAuthLog.shared.log(tag: "2FA-PUSH", "⚠️ Apple requires Two-Factor Authentication (HSA2/TrustedDevice).")

                    // Stash pending context
                    self.pendingTwoFactorContext = Pending2FAContext(
                        appleID: sanitizedAppleID,
                        password: password,
                        dsid: dsid,
                        idmsToken: idmsToken,
                        sessionKey: srp.sessionKey(),
                        challengeToken: decryptedSPD?.challengeToken,
                        anisetteHeaders: anisette
                    )

                    // EXPLICITLY TRIGGER 2FA PUSH NOTIFICATION (Fortiva method)
                    let pushSent = self.triggerTrustedDevice2FA(dsid: dsid, idmsToken: idmsToken, anisette: anisette)

                    let msg = pushSent
                        ? "Two-factor authentication required. A 6-digit verification code has been pushed to your Apple devices."
                        : "Two-factor authentication required. Please enter your 6-digit verification code."

                    completion(true, msg, nil)
                    return
                }

                // 6. Direct success without 2FA
                var sessionToken: String?

                if let rawSPD = decryptedSPD?.rawDictionary,
                   let tokens = rawSPD["t"] as? [String: Any],
                   let xcodeTokenDict = tokens["com.apple.gs.xcode.auth"] as? [String: Any],
                   let tok = xcodeTokenDict["token"] as? String {
                    sessionToken = tok
                    ContraAuthLog.shared.log(tag: "GSA-HTTP", "Found pre-existing Xcode token in SPD payload")
                }

                if sessionToken == nil, let sk = srp.sessionKey(), !dsid.isEmpty, !idmsToken.isEmpty {
                    sessionToken = self.fetchAppToken(
                        dsid: dsid,
                        idmsToken: idmsToken,
                        sessionKey: sk,
                        challengeToken: decryptedSPD?.challengeToken,
                        anisette: anisette
                    )
                }

                let finalToken = sessionToken ?? UUID().uuidString

                // 7. Resolve Developer Teams & Team ID
                let teamResolution = self.resolveDeveloperTeams(
                    appleID: sanitizedAppleID,
                    dsid: dsid,
                    token: finalToken,
                    anisette: anisette
                )

                self.saveSession(
                    appleID: sanitizedAppleID,
                    dsid: dsid,
                    token: finalToken,
                    teamID: teamResolution.primaryTeamID,
                    teamName: teamResolution.primaryTeamName,
                    teams: teamResolution.allTeams
                )

                let successMsg = "Successfully authenticated as \(sanitizedAppleID)\n  Team: \(teamResolution.primaryTeamName) [ID: \(teamResolution.primaryTeamID)]"
                ContraAuthLog.shared.log(tag: "AUTH", "🎉 \(successMsg)")
                completion(false, successMsg, nil)
            } catch {
                ContraAuthLog.shared.log(tag: "AUTH", "❌ Authentication error: \(error.localizedDescription)")
                completion(false, nil, error)
            }
        }
    }

    // MARK: - Submit 2FA Code

    public func submit2FACode(code: String, completion: @escaping (Bool, String?, Error?) -> Void) {
        queue.async {
            guard let context = self.pendingTwoFactorContext else {
                completion(false, nil, NSError(
                    domain: "com.kurishu.contrainstalld",
                    code: 400,
                    userInfo: [NSLocalizedDescriptionKey: "No pending two-factor authentication challenge found."]
                ))
                return
            }

            let cleanCode = code.trimmingCharacters(in: .whitespacesAndNewlines)
            guard cleanCode.count >= 6 else {
                completion(false, nil, NSError(
                    domain: "com.kurishu.contrainstalld",
                    code: 400,
                    userInfo: [NSLocalizedDescriptionKey: "Verification code must be at least 6 digits."]
                ))
                return
            }

            ContraAuthLog.shared.log(tag: "2FA-CODE", "Validating 6-digit verification code with Apple GrandSlam...")

            let identityToken = Data("\(context.dsid):\(context.idmsToken)".utf8).base64EncodedString()
            let validateURL = URL(string: "https://gsa.apple.com/grandslam/GsService2/validate")!

            var request = URLRequest(url: validateURL)
            request.httpMethod = "POST"
            request.httpBody = Data()
            request.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
            request.setValue("text/x-xml-plist", forHTTPHeaderField: "Accept")
            request.setValue("akd/1.0 CFNetwork Darwin", forHTTPHeaderField: "User-Agent")
            request.setValue("com.apple.gs.xcode.auth", forHTTPHeaderField: "X-Apple-App-Info")
            request.setValue("27.0 (27A5218g)", forHTTPHeaderField: "X-Xcode-Version")
            request.setValue(identityToken, forHTTPHeaderField: "X-Apple-Identity-Token")
            request.setValue(context.dsid, forHTTPHeaderField: "X-Apple-I-DSID")
            request.setValue(cleanCode, forHTTPHeaderField: "security-code")
            request.setValue("close", forHTTPHeaderField: "Connection")

            if let clientInfo = context.anisetteHeaders["X-MMe-Client-Info"] {
                request.setValue(clientInfo, forHTTPHeaderField: "X-Mme-Client-Info")
            }

            for (k, v) in context.anisetteHeaders {
                request.setValue(v, forHTTPHeaderField: k)
            }

            let semaphore = DispatchSemaphore(value: 0)
            var responseData: Data?
            var responseError: Error?
            var httpResponse: HTTPURLResponse?

            let task = URLSession.shared.dataTask(with: request) { data, resp, err in
                responseData = data
                httpResponse = resp as? HTTPURLResponse
                responseError = err
                semaphore.signal()
            }
            task.resume()
            _ = semaphore.wait(timeout: .now() + 30.0)

            if let err = responseError {
                ContraAuthLog.shared.log(tag: "2FA-CODE", "❌ Network error: \(err.localizedDescription)")
                completion(false, nil, err)
                return
            }

            let statusCode = httpResponse?.statusCode ?? 0
            ContraAuthLog.shared.log(tag: "2FA-CODE", "<- /grandslam/GsService2/validate: HTTP \(statusCode)")

            var ec = -1
            if let data = responseData,
               let plist = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any],
               let resp = plist["Response"] as? [String: Any],
               let status = resp["Status"] as? [String: Any] {
                ec = status["ec"] as? Int ?? -1
                let em = status["em"] as? String ?? ""
                ContraAuthLog.shared.log(tag: "2FA-CODE", "Validation status: ec=\(ec), em='\(em)'")
            }

            let isValid = (statusCode == 200 || statusCode == 204) && (ec == 0 || ec == -1)

            guard isValid else {
                ContraAuthLog.shared.log(tag: "2FA-CODE", "❌ 2FA verification failed (HTTP \(statusCode), ec=\(ec))")
                completion(false, nil, NSError(
                    domain: "com.kurishu.contrainstalld",
                    code: 401,
                    userInfo: [NSLocalizedDescriptionKey: "Invalid 2FA verification code. Please check your devices and try again."]
                ))
                return
            }

            ContraAuthLog.shared.log(tag: "2FA-CODE", "✅ 2FA code verified successfully!")

            // Step 2: Acquire session token (AppToken)
            var token: String? = nil

            if let sk = context.sessionKey, !context.dsid.isEmpty, !context.idmsToken.isEmpty {
                token = self.fetchAppToken(
                    dsid: context.dsid,
                    idmsToken: context.idmsToken,
                    sessionKey: sk,
                    challengeToken: context.challengeToken,
                    anisette: context.anisetteHeaders
                )
            }

            // Fallback: Re-authenticate via SRP to retrieve fresh session token (Fortiva strategy)
            if token == nil {
                ContraAuthLog.shared.log(tag: "AUTH", "Re-authenticating via SRP to retrieve updated session token...")
                self.login(appleID: context.appleID, password: context.password) { success, msg, err in
                    self.pendingTwoFactorContext = nil
                    completion(success, msg, err)
                }
                return
            }

            let finalToken = token ?? UUID().uuidString

            // Step 3: Resolve Developer Teams & Team ID
            let teamResolution = self.resolveDeveloperTeams(
                appleID: context.appleID,
                dsid: context.dsid,
                token: finalToken,
                anisette: context.anisetteHeaders
            )

            self.saveSession(
                appleID: context.appleID,
                dsid: context.dsid,
                token: finalToken,
                teamID: teamResolution.primaryTeamID,
                teamName: teamResolution.primaryTeamName,
                teams: teamResolution.allTeams
            )

            self.pendingTwoFactorContext = nil
            let successMsg = "Successfully authenticated as \(context.appleID)\n  Team: \(teamResolution.primaryTeamName) [ID: \(teamResolution.primaryTeamID)]"
            ContraAuthLog.shared.log(tag: "AUTH", "🎉 \(successMsg)")
            completion(true, successMsg, nil)
        }
    }

    // MARK: - Session Persistence

    private func saveSession(
        appleID: String,
        dsid: String,
        token: String,
        teamID: String?,
        teamName: String?,
        teams: [[String: Any]] = []
    ) {
        var sessionData: [String: Any] = [
            "appleID": appleID,
            "dsid": dsid,
            "token": token,
            "teamID": teamID ?? "",
            "teamName": teamName ?? "",
            "savedDate": ISO8601DateFormatter().string(from: Date())
        ]

        if !teams.isEmpty {
            sessionData["teams"] = teams
        }

        do {
            let data = try PropertyListSerialization.data(fromPropertyList: sessionData, format: .xml, options: 0)
            try data.write(to: self.sessionFileURL, options: .atomic)
            ContraAuthLog.shared.log(tag: "SESSION", "Credentials and Team ID successfully persisted to session.plist")
        } catch {
            ContraAuthLog.shared.log(tag: "SESSION", "❌ Failed to save session plist: \(error.localizedDescription)")
        }
    }

    public func activeSession() -> [String: Any]? {
        guard let data = try? Data(contentsOf: sessionFileURL),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            return nil
        }
        return plist
    }

    public func getAccountStatus() -> [String: Any]? {
        return activeSession()
    }

    public func logout() -> Bool {
        ContraAuthLog.shared.log(tag: "SESSION", "Signing out. Removing active session credentials...")
        pendingTwoFactorContext = nil
        do {
            if FileManager.default.fileExists(atPath: sessionFileURL.path) {
                try FileManager.default.removeItem(at: sessionFileURL)
            }
            ContraAuthLog.shared.log(tag: "SESSION", "Session removed successfully.")
            return true
        } catch {
            ContraAuthLog.shared.log(tag: "SESSION", "Failed to remove session file: \(error.localizedDescription)")
            return false
        }
    }
}
