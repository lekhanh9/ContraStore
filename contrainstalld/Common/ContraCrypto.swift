//
//  ContraCrypto.swift
//  contrainstalld
//
//  Cryptographic utilities for Apple SRP-6a authentication, PBKDF2, AES-CBC, and AES-GCM.
//  Uses Apple native CryptoKit and CommonCrypto frameworks.
//

import Foundation
import CryptoKit
import CommonCrypto

public enum ContraCrypto {

    /// Computes HMAC-SHA256 over raw Data
    public static func hmacSHA256(key: Data, data: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let authCode = HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey)
        return Data(authCode)
    }

    /// Computes HMAC-SHA256 over concatenated strings
    public static func hmacSHA256(key: Data, strings: [String]) -> Data {
        var concatenated = Data()
        for s in strings {
            concatenated.append(Data(s.utf8))
        }
        return hmacSHA256(key: key, data: concatenated)
    }

    /// Returns SHA-256 digest of data
    public static func sha256(_ data: Data) -> Data {
        let digest = SHA256.hash(data: data)
        return Data(digest)
    }

    /// Derives key using PBKDF2-HMAC-SHA256 via CommonCrypto
    public static func pbkdf2SHA256(
        password: Data,
        salt: Data,
        rounds: Int,
        outputLength: Int
    ) -> Data? {
        guard rounds > 0, outputLength > 0 else { return nil }
        var derivedKey = Data(count: outputLength)

        let status = derivedKey.withUnsafeMutableBytes { derivedBuf -> Int32 in
            guard let derivedPtr = derivedBuf.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return password.withUnsafeBytes { passBuf -> Int32 in
                guard let passPtr = passBuf.bindMemory(to: Int8.self).baseAddress else { return -1 }
                return salt.withUnsafeBytes { saltBuf -> Int32 in
                    guard let saltPtr = saltBuf.bindMemory(to: UInt8.self).baseAddress else { return -1 }
                    return CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passPtr,
                        password.count,
                        saltPtr,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(rounds),
                        derivedPtr,
                        outputLength
                    )
                }
            }
        }

        guard status == kCCSuccess else { return nil }
        return derivedKey
    }

    /// Decrypts AES-CBC encrypted ciphertext with PKCS#7 unpadding via CommonCrypto
    public static func aesCBCDecrypt(key: Data, iv: Data, ciphertext: Data) -> Data? {
        guard iv.count >= 16 else { return nil }
        guard key.count == 16 || key.count == 24 || key.count == 32 else { return nil }
        guard !ciphertext.isEmpty, ciphertext.count % 16 == 0 else { return nil }

        var output = Data(count: ciphertext.count + Int(kCCBlockSizeAES128))
        var numBytesDecrypted: size_t = 0

        let status = output.withUnsafeMutableBytes { outBuf in
            ciphertext.withUnsafeBytes { cipherBuf in
                key.withUnsafeBytes { keyBuf in
                    iv.prefix(16).withUnsafeBytes { ivBuf in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBuf.baseAddress,
                            key.count,
                            ivBuf.baseAddress,
                            cipherBuf.baseAddress,
                            ciphertext.count,
                            outBuf.baseAddress,
                            outBuf.count,
                            &numBytesDecrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else { return nil }
        output.count = numBytesDecrypted
        return output
    }

    /// Encrypts plaintext with AES-CBC with PKCS#7 padding via CommonCrypto
    public static func aesCBCEncrypt(key: Data, iv: Data, plaintext: Data) -> Data? {
        guard iv.count >= 16 else { return nil }
        guard key.count == 16 || key.count == 24 || key.count == 32 else { return nil }

        var output = Data(count: plaintext.count + Int(kCCBlockSizeAES128))
        var numBytesEncrypted: size_t = 0

        let status = output.withUnsafeMutableBytes { outBuf in
            plaintext.withUnsafeBytes { plainBuf in
                key.withUnsafeBytes { keyBuf in
                    iv.prefix(16).withUnsafeBytes { ivBuf in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBuf.baseAddress,
                            key.count,
                            ivBuf.baseAddress,
                            plainBuf.baseAddress,
                            plaintext.count,
                            outBuf.baseAddress,
                            outBuf.count,
                            &numBytesEncrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else { return nil }
        output.count = numBytesEncrypted
        return output
    }

    /// Decrypts ciphertext with AES-GCM using key, nonce, aad, and tag via CryptoKit
    public static func aesGCMDecrypt(
        key: Data,
        nonce: Data,
        aad: Data,
        ciphertext: Data,
        tag: Data
    ) -> Data? {
        guard key.count == 16 || key.count == 24 || key.count == 32 else { return nil }
        guard let gcmNonce = try? AES.GCM.Nonce(data: nonce) else { return nil }
        guard tag.count == 16 else { return nil }

        do {
            let sealedBox = try AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ciphertext, tag: tag)
            let symmetricKey = SymmetricKey(data: key)
            if aad.isEmpty {
                return try AES.GCM.open(sealedBox, using: symmetricKey)
            } else {
                return try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: aad)
            }
        } catch {
            return nil
        }
    }
}
