// SPDX-License-Identifier: Apache-2.0
//
// Rung 3b — Secure Enclave key-custody helper.
//
// Generates an EPHEMERAL P-256 key inside the Secure Enclave
// (kSecAttrTokenIDSecureEnclave) and signs one caller-supplied message with
// it, then exits. The private key is never made kSecAttrIsPermanent (that
// requires a keychain-access-groups entitlement this ad-hoc-signed tool does
// not have — persistent SEP keys failed with -34018 "missing entitlement" in
// testing) and is never exported: SecKeyCopyExternalRepresentation is called
// only on the PUBLIC half. Ephemeral does not mean "not hardware-backed" —
// the keygen and the signature both happen inside the Secure Enclave chip;
// it only means this exact key is not retrievable after the process exits,
// which is fine because sep_attestation.py signs once and caches the
// resulting attestation (not the key).
//
// Access control is kSecAttrAccessibleWhenUnlockedThisDeviceOnly +
// .privateKeyUsage — device-unlock only, deliberately NO biometry flag
// (.biometryCurrentSet / .userPresence), so this runs unattended on a
// headless node.
//
// Usage:
//   swift sep_attestation_helper.swift attest <hex-message>
//   swift sep_attestation_helper.swift extract-attempt   (red-team only, see below)
//
// Output (stdout, one line of JSON):
//   ok:   {"ok":true,"custody":"secure_enclave","algorithm":"ecdsa-p256-sha256",
//          "public_key_x963_hex":"04...","signature_der_hex":"30..."}
//   fail: {"ok":false,"error":"<description>"}
//
// Any failure (no SEP on this Mac, non-Apple hardware, sandboxed/denied
// access) is reported as {"ok":false,...} on stdout with a non-zero exit
// code — never a crash, never a partial/ambiguous result. The caller
// (sep_attestation.py) treats anything other than a clean {"ok":true,...}
// as "fall back to a software key," and labels that fallback honestly.
//
// `extract-attempt` is RED-TEAM TOOLING (docs/REDTEAM-RUNG3.md, "key
// extraction attempt"), never called by sep_attestation.py: it generates a
// Secure Enclave key exactly as `attest` does, then calls
// SecKeyCopyExternalRepresentation on the PRIVATE key reference itself (not
// the public key) to demonstrate hardware-enforced non-exportability. This
// is expected to FAIL — the Secure Enclave physically never releases private
// key bytes to any process, ours included — and the JSON reports whether
// that hardware guarantee held.

import Foundation
import Security

func emit(_ obj: [String: Any]) -> Never {
    let data = try! JSONSerialization.data(withJSONObject: obj)
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write("\n".data(using: .utf8)!)
    exit(obj["ok"] as? Bool == true ? 0 : 1)
}

func hexDecode(_ hex: String) -> Data? {
    var data = Data()
    var s = Substring(hex)
    if s.count % 2 != 0 { return nil }
    while !s.isEmpty {
        let next = s.index(s.startIndex, offsetBy: 2)
        guard let byte = UInt8(s[s.startIndex..<next], radix: 16) else { return nil }
        data.append(byte)
        s = s[next...]
    }
    return data
}

func hexEncode(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

func generateSepKey(_ cfError: inout Unmanaged<CFError>?) -> SecKey? {
    guard let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        .privateKeyUsage,
        &cfError
    ) else {
        return nil
    }
    let keyAttrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: false,
            kSecAttrAccessControl as String: access,
        ],
    ]
    return SecKeyCreateRandomKey(keyAttrs as CFDictionary, &cfError)
}

let args = CommandLine.arguments
let mode = args.count >= 2 ? args[1] : ""

if mode == "extract-attempt" {
    var cfError: Unmanaged<CFError>?
    guard let privateKey = generateSepKey(&cfError) else {
        emit(["ok": false, "error": "could not even generate a Secure Enclave key to attempt extraction on: \(String(describing: cfError))"])
    }
    // The actual red-team probe: ask the OS for the PRIVATE key's raw bytes.
    if let rep = SecKeyCopyExternalRepresentation(privateKey, &cfError) as Data? {
        // Should never happen -- if it does, the hardware guarantee broke.
        emit(["ok": true, "extraction_succeeded": true, "leaked_bytes_hex": hexEncode(rep)])
    } else {
        emit([
            "ok": true,
            "extraction_succeeded": false,
            "error": "SecKeyCopyExternalRepresentation on the SEP private key failed (expected): \(String(describing: cfError))",
        ])
    }
}

guard mode == "attest", args.count >= 3 else {
    emit(["ok": false, "error": "usage: sep_attestation_helper.swift attest <hex-message> | extract-attempt"])
}

guard let message = hexDecode(args[2]) else {
    emit(["ok": false, "error": "message must be lowercase hex"])
}

var cfError: Unmanaged<CFError>?
guard let privateKey = generateSepKey(&cfError) else {
    emit(["ok": false, "error": "SecKeyCreateRandomKey (Secure Enclave) failed: \(String(describing: cfError))"])
}

guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
    emit(["ok": false, "error": "SecKeyCopyPublicKey returned nil"])
}

guard let pubRep = SecKeyCopyExternalRepresentation(publicKey, &cfError) as Data? else {
    emit(["ok": false, "error": "SecKeyCopyExternalRepresentation (public) failed: \(String(describing: cfError))"])
}

guard let signature = SecKeyCreateSignature(
    privateKey,
    .ecdsaSignatureMessageX962SHA256,
    message as CFData,
    &cfError
) as Data? else {
    emit(["ok": false, "error": "SecKeyCreateSignature failed: \(String(describing: cfError))"])
}

emit([
    "ok": true,
    "custody": "secure_enclave",
    "algorithm": "ecdsa-p256-sha256",
    "public_key_x963_hex": hexEncode(pubRep),
    "signature_der_hex": hexEncode(signature),
])
