//
//  ContraSRPClient.swift
//  contrainstalld
//
//  SRP-6a client implementation with RFC 5054 2048-bit prime group for Apple GSA authentication.
//

import Foundation

public struct DecryptedSPD: @unchecked Sendable {
    public let dsid: String
    public let idmsToken: String
    public let sessionKey: Data
    public let challengeToken: Data?
    public let rawDictionary: [String: Any]
}

public final class ContraSRPClient {

    // RFC 5054 2048-bit MODP Group Prime (N)
    private static let N_Hex = """
    AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050\
    A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50\
    E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8\
    55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B\
    CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748\
    544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6\
    AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6\
    94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73
    """

    private static let N_Bytes: Data = Data(hexString: N_Hex)!
    private static let g_Val: UInt32 = 2
    public static let GroupSize: Int = 256

    private let bnN: BigUInt
    private let bng: BigUInt
    private let bnk: BigUInt

    private var bna: BigUInt?
    private var bnA: BigUInt?
    private var bnK: Data?
    private var expectedM2: Data?

    public init() {
        let n = BigUInt(data: Self.N_Bytes)
        let g = BigUInt(UInt64(Self.g_Val))
        self.bnN = n
        self.bng = g

        // Compute k = SHA256(N || pad(g))
        var gPadded = Data(repeating: 0, count: Self.GroupSize - 1)
        gPadded.append(UInt8(Self.g_Val))
        let kBytes = ContraCrypto.sha256(Self.N_Bytes + gPadded)
        self.bnk = BigUInt(data: kBytes)
    }

    /// Generates client ephemeral private key 'a' and returns public key 'A' (256 bytes).
    public func startAuthentication() -> Data {
        let a = BigUInt.random(bitWidth: 256)
        let A = bng.power(a, modulus: bnN)

        self.bna = a
        self.bnA = A

        return A.serialize(paddedTo: Self.GroupSize)
    }

    /// Derives the password key using PBKDF2 with either raw SHA256 bytes (s2k) or hex bytes (s2k_fo).
    public func derivePasswordKey(
        password: String,
        salt: Data,
        iterations: Int,
        isS2KFO: Bool
    ) -> Data? {
        guard let passwordData = password.data(using: .utf8) else { return nil }
        let digest = ContraCrypto.sha256(passwordData)

        let inputDigest: Data
        if isS2KFO {
            let hexStr = digest.map { String(format: "%02x", $0) }.joined()
            inputDigest = Data(hexStr.utf8)
        } else {
            inputDigest = digest
        }

        return ContraCrypto.pbkdf2SHA256(
            password: inputDigest,
            salt: salt,
            rounds: iterations,
            outputLength: digest.count
        )
    }

    /// Processes server challenge (B, salt) and returns client verification proof M1.
    public func processChallenge(
        username: String,
        derivedPasswordKey: Data,
        salt: Data,
        serverPublicKey bData: Data
    ) -> Data? {
        guard let bna = self.bna, let bnA = self.bnA else { return nil }

        let bnB = BigUInt(data: bData)
        guard !(bnB % bnN).isZero else { return nil }

        let aData = bnA.serialize(paddedTo: Self.GroupSize)

        // u = SHA256(A || B)
        let uData = ContraCrypto.sha256(aData + bData)
        let bnu = BigUInt(data: uData)
        guard !bnu.isZero else { return nil }

        // CoreCrypto SRP derives x as:
        // h1 = SHA256(":" || password)
        // x  = SHA256(salt || h1)
        let h1 = ContraCrypto.sha256(Data(":".utf8) + derivedPasswordKey)
        let xHash = ContraCrypto.sha256(salt + h1)
        let bnx = BigUInt(data: xHash)

        // v = g^x mod N
        let bnv = bng.power(bnx, modulus: bnN)

        // Base = (B - k*v) mod N
        let bnkv = (bnk * bnv) % bnN
        let bnBase = bnB.modSub(bnkv, modulus: bnN)

        // Exp = (a + u*x)
        let bnux = bnu * bnx
        let bnExp = bna + bnux

        // S = Base^Exp mod N
        let bnS = bnBase.power(bnExp, modulus: bnN)
        let sBytes = bnS.serialize(paddedTo: Self.GroupSize)

        // Master session key K = SHA256(S)
        let kSessionData = ContraCrypto.sha256(sBytes)
        self.bnK = kSessionData

        // M1 = SHA256(H(N) ^ H(g) || H(U) || salt || A || B || K)
        let hn = ContraCrypto.sha256(Self.N_Bytes)
        var gPadded = Data(repeating: 0, count: Self.GroupSize - 1)
        gPadded.append(UInt8(Self.g_Val))
        let hg = ContraCrypto.sha256(gPadded)

        var hXor = Data(count: 32)
        for i in 0..<32 {
            hXor[i] = hn[i] ^ hg[i]
        }

        let hu = ContraCrypto.sha256(Data(username.utf8))
        let m1Payload = hXor + hu + salt + aData + bData + kSessionData
        let m1Data = ContraCrypto.sha256(m1Payload)

        // Expected M2 = SHA256(A || M1 || K)
        let m2Payload = aData + m1Data + kSessionData
        self.expectedM2 = ContraCrypto.sha256(m2Payload)

        return m1Data
    }

    /// Verifies server proof M2.
    public func verifyServerProof(_ proof: Data) -> Bool {
        guard let expected = self.expectedM2 else { return false }
        return proof == expected
    }

    /// Returns the negotiated session key K (32 bytes).
    public func sessionKey() -> Data? {
        return self.bnK
    }

    /// Decrypts AES-CBC encrypted SPD payload from GrandSlam complete response.
    public func decryptSPD(_ spd: Data) throws -> DecryptedSPD {
        guard let k = self.bnK else {
            throw NSError(domain: "com.kurishu.contra", code: -1, userInfo: [NSLocalizedDescriptionKey: "Missing SRP session key."])
        }

        let spdKey = ContraCrypto.hmacSHA256(key: k, strings: ["extra data key:"])
        let spdIV = ContraCrypto.hmacSHA256(key: k, strings: ["extra data iv:"])

        guard let decrypted = ContraCrypto.aesCBCDecrypt(key: spdKey, iv: spdIV, ciphertext: spd) else {
            throw NSError(domain: "com.kurishu.contra", code: -2, userInfo: [NSLocalizedDescriptionKey: "Failed to AES-CBC decrypt SPD payload."])
        }

        guard let plist = try? PropertyListSerialization.propertyList(from: decrypted, options: [], format: nil) as? [String: Any] else {
            throw NSError(domain: "com.kurishu.contra", code: -3, userInfo: [NSLocalizedDescriptionKey: "SPD decrypted payload is not a valid property list."])
        }

        let adsid = plist["adsid"] as? String
        let dsidString = (plist["dsid"] as? CustomStringConvertible)?.description
        guard let dsid = adsid ?? dsidString else {
            throw NSError(domain: "com.kurishu.contra", code: -4, userInfo: [NSLocalizedDescriptionKey: "SPD missing adsid/dsid."])
        }

        let gsToken = plist["GsIdmsToken"] as? String
        let idmsToken = plist["idmsToken"] as? String
        guard let token = gsToken ?? idmsToken else {
            throw NSError(domain: "com.kurishu.contra", code: -5, userInfo: [NSLocalizedDescriptionKey: "SPD missing GsIdmsToken."])
        }

        let sk = plist["sk"] as? Data ?? Data()
        let c = plist["c"] as? Data

        return DecryptedSPD(
            dsid: dsid,
            idmsToken: token,
            sessionKey: sk,
            challengeToken: c,
            rawDictionary: plist
        )
    }

    /// Decrypts AES-GCM encrypted Xcode app token from 'et' payload.
    public static func decryptAppToken(
        encryptedToken: Data,
        sessionKey: Data,
        targetApp: String = "com.apple.gs.xcode.auth"
    ) throws -> (token: String, expirationDate: Date?) {
        guard encryptedToken.count > 35 else {
            throw NSError(domain: "com.kurishu.contra", code: -6, userInfo: [NSLocalizedDescriptionKey: "Encrypted token payload too short."])
        }

        let aad = Data(encryptedToken[..<3])
        let nonce = Data(encryptedToken[3..<19])
        let ciphertext = Data(encryptedToken[19..<(encryptedToken.count - 16)])
        let tag = Data(encryptedToken[(encryptedToken.count - 16)...])

        guard let decrypted = ContraCrypto.aesGCMDecrypt(key: sessionKey, nonce: nonce, aad: aad, ciphertext: ciphertext, tag: tag) else {
            throw NSError(domain: "com.kurishu.contra", code: -7, userInfo: [NSLocalizedDescriptionKey: "Failed to AES-GCM decrypt application token."])
        }

        guard let plist = try? PropertyListSerialization.propertyList(from: decrypted, options: [], format: nil) as? [String: Any],
              let appTokens = plist["t"] as? [String: Any],
              let tokenDict = appTokens[targetApp] as? [String: Any],
              let token = tokenDict["token"] as? String
        else {
            throw NSError(domain: "com.kurishu.contra", code: -8, userInfo: [NSLocalizedDescriptionKey: "Failed to parse decrypted app token payload."])
        }

        var expirationDate: Date? = nil
        if let expiry = tokenDict["expiry"] as? Date {
            expirationDate = expiry
        } else if let expiryNum = tokenDict["expiry"] as? Double {
            expirationDate = Date(timeIntervalSince1970: expiryNum / 1000.0)
        } else if let ttl = tokenDict["ttl"] as? Double {
            expirationDate = Date().addingTimeInterval(ttl)
        }

        return (token: token, expirationDate: expirationDate)
    }
}

fileprivate extension Data {
    init?(hexString: String) {
        let cleaned = hexString.replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: "\t", with: "")
        guard cleaned.count % 2 == 0 else { return nil }
        var data = Data(capacity: cleaned.count / 2)
        var index = cleaned.startIndex
        while index < cleaned.endIndex {
            let nextIndex = cleaned.index(index, offsetBy: 2)
            let byteStr = String(cleaned[index..<nextIndex])
            guard let byte = UInt8(byteStr, radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
}
