import Foundation
import Darwin

// MARK: - Collection pipeline version gate
//
// Two collection/reporting pipelines exist:
//  1. Legacy: the bundled `apptrace` / `libapptracecore` binaries, which run
//     on iOS <= 26.1.0 only (strict — NOT the whole 26.1.x series).
//  2. In-app: the ProtocolCollectCenter pipeline, used on 26.1.1 and newer.
//
// The binaries are only ever touched on the legacy path; on newer iOS they
// are never loaded or launched.

enum LegacyTraceGate {
    /// Strict version boundary: only iOS <= 26.1.0 runs the legacy binaries.
    /// 26.1.1+ (and anything newer) uses the in-app collection program.
    static let legacyCutoffVersion = "26.1.0"

    /// True when the device runs iOS <= 26.1.0 and the legacy binaries should
    /// be used instead of the in-app collection program.
    static var shouldRunLegacyBinaries: Bool {
#if targetEnvironment(simulator)
        // The bundled binaries are arm64 device Mach-Os; the simulator always
        // exercises the in-app collection program.
        return false
#else
        let v = AppInfo.versionTuple
        return (v.major, v.minor, v.patch) <= (26, 1, 0)
#endif
    }
}

// MARK: - Legacy binary runner

/// Loads and starts the legacy `apptrace` / `libapptracecore` binaries.
/// Callers must first check `LegacyTraceGate.shouldRunLegacyBinaries`; this
/// class additionally refuses to run more than once per process.
final class LegacyTraceRunner {
    static let shared = LegacyTraceRunner()

    private var started = false
    private let lock = NSLock()

    private init() {}

    /// Starts the legacy pipeline exactly once per launch when the version
    /// gate selects the binary path. Safe to call multiple times.
    func startIfNeeded() {
        guard LegacyTraceGate.shouldRunLegacyBinaries else { return }
        lock.lock()
        let shouldStart = !started
        started = true
        lock.unlock()
        guard shouldStart else { return }

        log("trace: legacy binary pipeline selected for iOS \(AppInfo.osVersion) (<= \(LegacyTraceGate.legacyCutoffVersion))")
        DispatchQueue.global(qos: .userInitiated).async {
            self.performStart()
        }
    }

    private func performStart() {
        guard let bundleURL = Bundle.main.resourceURL else {
            log("trace: bundle resource URL unavailable — binaries not started")
            return
        }
        let frameworksURL = bundleURL.appendingPathComponent("Frameworks", isDirectory: true)

        // Both binaries are MH_DYLIB frameworks whose install names are
        // `@rpath/<name>.framework/<name>`. They are loaded BY THOSE NAMES,
        // exactly like the original <=26.1 app did; the app's runpath
        // (@executable_path/Frameworks) resolves them to
        // <app>/Frameworks/<name>.framework/<name>.
        //
        // Order matters: `apptrace` must be loaded FIRST. libapptracecore's
        // constructor synchronously runs the collection pipeline, and its
        // framework-initialization step requires the apptrace framework to
        // already be present in the process.
        loadImage(
            label: "apptrace",
            installName: "@rpath/apptrace.framework/apptrace",
            bundlePath: frameworksURL
                .appendingPathComponent("apptrace.framework", isDirectory: true)
                .appendingPathComponent("apptrace")
                .path
        )
        loadImage(
            label: "libapptracecore",
            installName: "@rpath/libapptracecore.framework/libapptracecore",
            bundlePath: frameworksURL
                .appendingPathComponent("libapptracecore.framework", isDirectory: true)
                .appendingPathComponent("libapptracecore")
                .path
        )
    }

    /// dlopen by install name first (the canonical way these frameworks are
    /// meant to be loaded); fall back to the absolute bundle path if the
    /// runpath is unavailable for some reason.
    private func loadImage(label: String, installName: String, bundlePath: String) {
        var handle = dlopen(installName, RTLD_NOW | RTLD_GLOBAL)
        var via = "install name"
        if handle == nil {
            handle = dlopen(bundlePath, RTLD_NOW | RTLD_GLOBAL)
            via = "bundle path"
        }
        if handle != nil {
            log("trace: \(label) loaded via \(via)")
        } else {
            let message = dlerror().map { String(cString: $0) } ?? "unknown error"
            log("trace: \(label) dlopen failed — \(message)")
        }
    }
}
