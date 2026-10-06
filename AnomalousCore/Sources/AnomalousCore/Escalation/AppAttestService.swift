import Foundation
import CryptoKit
#if canImport(DeviceCheck)
import DeviceCheck
#endif

/// Supplies App Attest headers for an outgoing anonymous request. A nil provider
/// (e.g. the E2E CLI, which isn't a signed app) leaves the client on its dev
/// placeholder; the real `AppAttestService` returns genuine attestation headers.
public protocol AttestationProviding: Sendable {
    /// Headers to attach for a request whose body is exactly `body`. An empty
    /// dictionary means attestation is unavailable — the caller sends without
    /// them and the (fail-closed) server rejects, which is the correct outcome.
    func headers(for body: Data) async -> [String: String]
}

public enum AppAttestError: Error, Equatable {
    case unsupported
    case challengeFailed(Int)
    case registrationFailed(Int)
    case keyReplacementThrottled
}

/// Real App Attest (`DCAppAttestService`): generates a Secure-Enclave key once,
/// registers it with the server (one-time challenge → attestation object), then
/// signs every request with a per-request assertion. The key id is not secret
/// (it identifies the sensor build, never a user — the ingest anonymity
/// invariant), so it persists in `UserDefaults`; the private key lives in the
/// Secure Enclave, referenced by that id.
///
/// The wire contract is verified end-to-end against the server in
/// AttestRegistrationTest: challenge → attestKey(SHA256(challenge)) →
/// POST /attest/register, then generateAssertion(SHA256(body)) per request.
public actor AppAttestService: AttestationProviding {
    private let baseURL: URL
    private let defaults: UserDefaults
    private let keyIdKey: String
    private let registeredKey: String

    static func registrationKeys(for baseURL: URL) -> (keyID: String, registered: String) {
        let scope = SHA256.hash(data: Data(baseURL.absoluteString.utf8))
            .map { String(format: "%02x", $0) }.joined()
        return ("appAttestKeyId.\(scope)", "appAttestRegistered.\(scope)")
    }

    /// Dedupes concurrent first-use so two requests don't both try to register.
    private var registration: Task<String, Error>?

    public init(baseURL: URL, defaults: UserDefaults = .standard) {
        self.baseURL = baseURL
        self.defaults = defaults
        let keys = Self.registrationKeys(for: baseURL)
        self.keyIdKey = keys.keyID
        self.registeredKey = keys.registered
    }

    /// A stored key the device can no longer sign with is replaced at most this
    /// often per server, so a transient system failure can't churn keys.
    static let keyReplacementInterval: TimeInterval = 24 * 60 * 60

    static func replacedAtKey(for baseURL: URL) -> String {
        "appAttestReplacedAt." + registrationKeys(for: baseURL).keyID.dropFirst("appAttestKeyId.".count)
    }

    static func mayReplaceKey(lastReplaced: Date?, now: Date = Date()) -> Bool {
        guard let lastReplaced else { return true }
        return now.timeIntervalSince(lastReplaced) >= keyReplacementInterval
    }

    public func headers(for body: Data) async -> [String: String] {
        #if canImport(DeviceCheck)
        var stage = "registration"
        do {
            let keyId = try await ensureRegisteredKey()
            stage = "assertion"
            do {
                return try await assertionHeaders(keyId: keyId, body: body)
            } catch {
                // Self-heal. A key that was registered once but can no longer
                // sign (a restored or migrated Mac, an OS change, a reset Secure
                // Enclave) fails on every request, and nothing else ever replaces
                // it — the user is stuck on "couldn't verify this app". Register
                // one fresh key and retry once.
                print("[anomalous] App Attest assertion failed for the stored key; replacing it")
                let fresh = try await replaceKey(failed: keyId)
                return try await assertionHeaders(keyId: fresh, body: body)
            }
        } catch {
            let diagnostic = error as NSError
            print("[anomalous] App Attest \(stage) failed: \(diagnostic.domain) code \(diagnostic.code); supported=\(DCAppAttestService.shared.isSupported); error=\(String(describing: error as? AppAttestError))")
            // Fail closed: no valid attestation → no headers. Better a rejected
            // request than a placeholder that would poison the corpus if a
            // misconfigured server ever accepted it.
            return [:]
        }
        #else
        return [:]
        #endif
    }

    // MARK: - Registration

    private func ensureRegisteredKey() async throws -> String {
        // Legacy unscoped registrations have no trustworthy server provenance.
        if let keyId = defaults.string(forKey: keyIdKey), defaults.bool(forKey: registeredKey) {
            return keyId
        }
        if let registration { return try await registration.value }

        let task = Task { try await self.register() }
        registration = task
        defer { registration = nil }
        return try await task.value
    }

    #if canImport(DeviceCheck)
    private func assertionHeaders(keyId: String, body: Data) async throws -> [String: String] {
        let clientDataHash = Data(SHA256.hash(data: body))
        let assertion = try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: clientDataHash)
        return [
            "X-Anomalous-Key-Id": keyId,
            "X-Anomalous-Assertion": assertion.base64EncodedString(),
        ]
    }

    /// Replace a key the device can no longer sign with. Concurrent requests
    /// share one replacement: if the stored key already differs from the one
    /// that failed, another request replaced it, so use that.
    private func replaceKey(failed keyId: String) async throws -> String {
        if let current = defaults.string(forKey: keyIdKey), current != keyId, defaults.bool(forKey: registeredKey) {
            return current
        }
        let replacedAt = Self.replacedAtKey(for: baseURL)
        guard Self.mayReplaceKey(lastReplaced: defaults.object(forKey: replacedAt) as? Date) else {
            throw AppAttestError.keyReplacementThrottled
        }
        defaults.set(Date(), forKey: replacedAt)
        defaults.removeObject(forKey: keyIdKey)
        defaults.set(false, forKey: registeredKey)
        return try await ensureRegisteredKey()
    }

    private func register() async throws -> String {
        let service = DCAppAttestService.shared
        guard service.isSupported else { throw AppAttestError.unsupported }

        // attestKey is one-shot per key, so always start from a fresh key and
        // only persist it once the server has accepted the registration.
        let keyId = try await service.generateKey()
        do {
            let challenge = try await fetchChallenge()
            let attestation = try await service.attestKey(keyId, clientDataHash: Data(SHA256.hash(data: challenge)))
            try await postRegister(keyId: keyId, attestation: attestation, challenge: challenge)

            defaults.set(keyId, forKey: keyIdKey)
            defaults.set(true, forKey: registeredKey)
            return keyId
        } catch {
            // The key is now burned (attested, unregistered) or the network
            // failed — drop it so the next attempt generates a clean one.
            defaults.removeObject(forKey: keyIdKey)
            defaults.set(false, forKey: registeredKey)
            throw error
        }
    }

    /// POST /api/v1/attest/challenge → the one-time challenge (decoded bytes).
    private func fetchChallenge() async throws -> Data {
        var req = URLRequest(url: baseURL.appending(path: "/api/v1/attest/challenge"))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Accept")

        let (data, response) = try await ServerOverridePolicy.data(for: req)
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else { throw AppAttestError.challengeFailed(code) }

        struct Body: Decodable { let challenge: String }
        let decoded = try JSONDecoder().decode(Body.self, from: data)
        guard let challenge = Data(base64Encoded: decoded.challenge) else {
            throw AppAttestError.challengeFailed(code)
        }
        return challenge
    }

    /// POST /api/v1/attest/register {key_id, attestation, challenge}.
    private func postRegister(keyId: String, attestation: Data, challenge: Data) async throws {
        var req = URLRequest(url: baseURL.appending(path: "/api/v1/attest/register"))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.httpBody = try JSONSerialization.data(withJSONObject: [
            "key_id": keyId,
            "attestation": attestation.base64EncodedString(),
            "challenge": challenge.base64EncodedString(),
        ])

        let (_, response) = try await ServerOverridePolicy.data(for: req)
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 201 else { throw AppAttestError.registrationFailed(code) }
    }
    #else
    private func register() async throws -> String { throw AppAttestError.unsupported }
    #endif
}
