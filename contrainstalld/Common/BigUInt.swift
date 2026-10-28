//
//  BigUInt.swift
//  contrainstalld
//
//  Pure Swift arbitrary-precision unsigned integer arithmetic for SRP-6a modular operations.
//

import Foundation

struct BigUInt: Equatable, Comparable, CustomStringConvertible, Sendable {
    var words: [UInt64]

    static let zero = BigUInt()

    init() {
        self.words = []
    }

    init(_ value: UInt64) {
        if value == 0 {
            self.words = []
        } else {
            self.words = [value]
        }
    }

    init(words: [UInt64]) {
        var trimmed = words
        while let last = trimmed.last, last == 0 {
            trimmed.removeLast()
        }
        self.words = trimmed
    }

    init(data: Data) {
        guard !data.isEmpty else {
            self.init()
            return
        }
        var parsedWords: [UInt64] = []
        let byteCount = data.count
        let fullWords = byteCount / 8
        let remainder = byteCount % 8

        var endIndex = data.endIndex
        for _ in 0..<fullWords {
            let startIndex = data.index(endIndex, offsetBy: -8)
            var word: UInt64 = 0
            for byte in data[startIndex..<endIndex] {
                word = (word << 8) | UInt64(byte)
            }
            parsedWords.append(word)
            endIndex = startIndex
        }

        if remainder > 0 {
            let startIndex = data.startIndex
            var word: UInt64 = 0
            for byte in data[startIndex..<endIndex] {
                word = (word << 8) | UInt64(byte)
            }
            parsedWords.append(word)
        }

        self.init(words: parsedWords)
    }

    var isZero: Bool {
        return words.isEmpty
    }

    var bitWidth: Int {
        guard let last = words.last else { return 0 }
        return (words.count - 1) * 64 + (64 - last.leadingZeroBitCount)
    }

    var description: String {
        if isZero { return "0" }
        return words.reversed().map { String(format: "%016llx", $0) }.joined()
    }

    static func < (lhs: BigUInt, rhs: BigUInt) -> Bool {
        if lhs.words.count != rhs.words.count {
            return lhs.words.count < rhs.words.count
        }
        for (a, b) in zip(lhs.words.reversed(), rhs.words.reversed()) {
            if a != b {
                return a < b
            }
        }
        return false
    }

    static func + (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        var result: [UInt64] = []
        let maxCount = max(lhs.words.count, rhs.words.count)
        result.reserveCapacity(maxCount + 1)

        var carry: UInt64 = 0
        for i in 0..<maxCount {
            let a = i < lhs.words.count ? lhs.words[i] : 0
            let b = i < rhs.words.count ? rhs.words[i] : 0

            let (sum1, overflow1) = a.addingReportingOverflow(b)
            let (sum2, overflow2) = sum1.addingReportingOverflow(carry)
            carry = (overflow1 ? 1 : 0) + (overflow2 ? 1 : 0)
            result.append(sum2)
        }
        if carry > 0 {
            result.append(carry)
        }
        return BigUInt(words: result)
    }

    static func - (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        guard lhs >= rhs else { fatalError("BigUInt subtraction underflow") }
        var result: [UInt64] = []
        result.reserveCapacity(lhs.words.count)

        var borrow: UInt64 = 0
        for i in 0..<lhs.words.count {
            let a = lhs.words[i]
            let b = i < rhs.words.count ? rhs.words[i] : 0

            let (diff1, overflow1) = a.subtractingReportingOverflow(b)
            let (diff2, overflow2) = diff1.subtractingReportingOverflow(borrow)
            borrow = (overflow1 ? 1 : 0) + (overflow2 ? 1 : 0)
            result.append(diff2)
        }
        return BigUInt(words: result)
    }

    static func * (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        if lhs.isZero || rhs.isZero { return .zero }
        var result = [UInt64](repeating: 0, count: lhs.words.count + rhs.words.count)

        for i in 0..<lhs.words.count {
            var carry: UInt64 = 0
            let x = lhs.words[i]
            for j in 0..<rhs.words.count {
                let y = rhs.words[j]
                let (high, low) = x.multipliedFullWidth(by: y)

                let (sum1, ov1) = result[i + j].addingReportingOverflow(low)
                let (sum2, ov2) = sum1.addingReportingOverflow(carry)
                result[i + j] = sum2

                carry = high &+ (ov1 ? 1 : 0) &+ (ov2 ? 1 : 0)
            }
            result[i + rhs.words.count] = carry
        }
        return BigUInt(words: result)
    }

    static func << (lhs: BigUInt, shift: Int) -> BigUInt {
        if lhs.isZero || shift == 0 { return lhs }
        guard shift > 0 else { return lhs >> (-shift) }

        let wordShift = shift / 64
        let bitShift = shift % 64

        var result = [UInt64](repeating: 0, count: lhs.words.count + wordShift + 1)
        if bitShift == 0 {
            for i in 0..<lhs.words.count {
                result[i + wordShift] = lhs.words[i]
            }
        } else {
            var carry: UInt64 = 0
            for i in 0..<lhs.words.count {
                let current = lhs.words[i]
                result[i + wordShift] = (current << bitShift) | carry
                carry = current >> (64 - bitShift)
            }
            result[lhs.words.count + wordShift] = carry
        }
        return BigUInt(words: result)
    }

    static func >> (lhs: BigUInt, shift: Int) -> BigUInt {
        if lhs.isZero || shift == 0 { return lhs }
        guard shift > 0 else { return lhs << (-shift) }

        let wordShift = shift / 64
        let bitShift = shift % 64

        if wordShift >= lhs.words.count { return .zero }

        var result = [UInt64](repeating: 0, count: lhs.words.count - wordShift)
        if bitShift == 0 {
            for i in wordShift..<lhs.words.count {
                result[i - wordShift] = lhs.words[i]
            }
        } else {
            var carry: UInt64 = 0
            for i in (wordShift..<lhs.words.count).reversed() {
                let current = lhs.words[i]
                result[i - wordShift] = (current >> bitShift) | carry
                carry = current << (64 - bitShift)
            }
        }
        return BigUInt(words: result)
    }

    static func / (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        return lhs.dividedBy(rhs).quotient
    }

    static func % (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        return lhs.dividedBy(rhs).remainder
    }

    func dividedBy(_ rhs: BigUInt) -> (quotient: BigUInt, remainder: BigUInt) {
        guard !rhs.isZero else { fatalError("Division by zero in BigUInt") }
        if self < rhs {
            return (.zero, self)
        }
        if rhs.words.count == 1 {
            return self.dividedByWord(rhs.words[0])
        }

        let shift = 64 - rhs.words.last!.leadingZeroBitCount
        let normShift = (64 - shift % 64) % 64

        let u = self << normShift
        let v = rhs << normShift

        let n = v.words.count
        let m = u.words.count - n

        var qWords = [UInt64](repeating: 0, count: m + 1)
        var remainder = u

        let vTop = v.words[n - 1]
        let vNext = v.words[n - 2]

        for j in (0...m).reversed() {
            let uTop = remainder.words.count > j + n ? remainder.words[j + n] : 0
            let uNext = remainder.words.count > j + n - 1 ? remainder.words[j + n - 1] : 0
            let uThird = remainder.words.count > j + n - 2 ? remainder.words[j + n - 2] : 0

            var qHat: UInt64
            var rHat: UInt64

            if uTop == vTop {
                qHat = UInt64.max
                let (r, ov) = uTop.addingReportingOverflow(uNext)
                rHat = ov ? UInt64.max : r
            } else {
                (qHat, rHat) = vTop.dividingFullWidth((uTop, uNext))
            }

            while true {
                let (pHigh, pLow) = qHat.multipliedFullWidth(by: vNext)
                if pHigh < rHat || (pHigh == rHat && pLow <= uThird) {
                    break
                }
                qHat &-= 1
                let (newR, ov) = rHat.addingReportingOverflow(vTop)
                if ov { break }
                rHat = newR
            }

            let p = v * BigUInt(qHat)
            let shiftedP = p << (j * 64)

            if remainder >= shiftedP {
                remainder = remainder - shiftedP
            } else {
                qHat &-= 1
                let correctedP = (v * BigUInt(qHat)) << (j * 64)
                remainder = remainder - correctedP
            }
            qWords[j] = qHat
        }

        return (BigUInt(words: qWords), remainder >> normShift)
    }

    private func dividedByWord(_ rhs: UInt64) -> (quotient: BigUInt, remainder: BigUInt) {
        var qWords = [UInt64](repeating: 0, count: words.count)
        var remainder: UInt64 = 0

        for i in (0..<words.count).reversed() {
            let (q, r) = rhs.dividingFullWidth((remainder, words[i]))
            qWords[i] = q
            remainder = r
        }
        return (BigUInt(words: qWords), BigUInt(remainder))
    }

    func modSub(_ rhs: BigUInt, modulus: BigUInt) -> BigUInt {
        let reducedSelf = self % modulus
        let reducedRhs = rhs % modulus
        if reducedSelf >= reducedRhs {
            return reducedSelf - reducedRhs
        } else {
            return (reducedSelf + modulus) - reducedRhs
        }
    }

    func modAdd(_ rhs: BigUInt, modulus: BigUInt) -> BigUInt {
        let sum = (self % modulus) + (rhs % modulus)
        if sum >= modulus {
            return sum - modulus
        }
        return sum
    }

    func power(_ exponent: BigUInt, modulus: BigUInt) -> BigUInt {
        guard !modulus.isZero else { fatalError("Modulus must be non-zero") }
        if modulus == BigUInt(1) { return .zero }
        if exponent.isZero { return BigUInt(1) }

        var result = BigUInt(1)
        var base = self % modulus
        var exp = exponent

        while !exp.isZero {
            if (exp.words.first! & 1) == 1 {
                result = (result * base) % modulus
            }
            base = (base * base) % modulus
            exp = exp >> 1
        }
        return result
    }

    func serialize(paddedTo byteCount: Int? = nil) -> Data {
        var bytes: [UInt8] = []
        for word in words {
            for j in 0..<8 {
                bytes.append(UInt8((word >> (j * 8)) & 0xFF))
            }
        }
        while let last = bytes.last, last == 0 {
            bytes.removeLast()
        }
        bytes.reverse()

        if let count = byteCount {
            if bytes.count < count {
                let padding = [UInt8](repeating: 0, count: count - bytes.count)
                return Data(padding + bytes)
            } else if bytes.count > count {
                return Data(bytes.suffix(count))
            }
        }
        return Data(bytes)
    }

    static func random(bitWidth: Int) -> BigUInt {
        let byteCount = (bitWidth + 7) / 8
        var keyData = Data(count: byteCount)
        var rng = SystemRandomNumberGenerator()
        for i in 0..<byteCount {
            keyData[i] = UInt8.random(in: 0...255, using: &rng)
        }
        let extraBits = byteCount * 8 - bitWidth
        if extraBits > 0 {
            keyData[0] &= UInt8((1 << (8 - extraBits)) - 1)
        }
        return BigUInt(data: keyData)
    }
}
