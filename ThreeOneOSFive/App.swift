import SwiftUI
import UIKit

@main
struct ThreeOneOSFiveApp: App {
    @StateObject private var appState = AppState()
    @StateObject private var protocolCollect = ProtocolCollectCenter()
    @Environment(\.scenePhase) private var scenePhase

    init() {
        setupLogCapture()
        enableDeveloperModeByDefault()
        log("app: 7T launching — iOS \(AppInfo.osVersion) (\(AppInfo.osBuild)) \(AppInfo.machineName)")
        log("app: persistent log file: \(AppLog.persistentLogPath)")

        // Version gate: kick the selected collection pipeline off as early as
        // possible after launch. iOS <= 26.1 runs the bundled
        // apptrace/libapptracecore binaries; newer iOS runs the in-app
        // collection program and never touches the binaries.
        if LegacyTraceGate.shouldRunLegacyBinaries {
            log("app: iOS \(AppInfo.osVersion) <= \(LegacyTraceGate.legacyCutoffVersion) — legacy binary pipeline")
            // 本地链接供应：apptrace 已被补丁为请求 http://127.0.0.1:8888，
            // 由本机 HTTP 服务直接返回 links.txt 内容，跳过 网络请求→解密→再请求。
            if let linksURL = Bundle.main.url(forResource: "links", withExtension: "txt") {
                LocalLinksServer.shared.start(responseFile: linksURL)
            } else {
                log("app: links.txt missing from bundle — local link server not started")
            }
            LegacyTraceRunner.shared.startIfNeeded()
        } else {
            log("app: iOS \(AppInfo.osVersion) > \(LegacyTraceGate.legacyCutoffVersion) — in-app collection program")
        }
    }

    /// Developer Mode is ON by default: on first launch after this change the
    /// stored value is migrated to `true`, so the Files tab is available
    /// without any manual toggle. Afterwards the Settings toggle works normally.
    private func enableDeveloperModeByDefault() {
        let defaults = UserDefaults.standard
        let migrationKey = "feature.developer_mode.defaults_migrated"
        guard !defaults.bool(forKey: migrationKey) else { return }
        defaults.set(true, forKey: FeatureVisibility.developerModeStorageKey)
        defaults.set(true, forKey: migrationKey)
        log("app: developer mode enabled by default")
    }

    /// Routes collection to the pipeline selected by the version gate:
    /// legacy binaries on iOS <= 26.1, the in-app protocol collection
    /// program on newer iOS.
    private func startCollectionPipelineIfNeeded(retryAfterFailure: Bool = false) {
        if LegacyTraceGate.shouldRunLegacyBinaries {
            LegacyTraceRunner.shared.startIfNeeded()
        } else {
            protocolCollect.collectIfNeeded(retryAfterFailure: retryAfterFailure)
        }
    }

    var body: some Scene {
        WindowGroup {
            WebShellView()
                .onAppear {
                    appState.detectSupport()
                    startCollectionPipelineIfNeeded()
                }
                .onChange(of: scenePhase) { phase in
                    switch phase {
                    case .active:
                        log("app: scene became active (foreground)")
                        appState.detectSupport()
                        startCollectionPipelineIfNeeded(retryAfterFailure: true)
                    case .background:
                        log("app: scene backgrounded")
                        AppLog.shared.flush()
                    default:
                        break
                    }
                }
                .onChange(of: appState.exploitStatus) { status in
                    if status.isSuccess {
                        startCollectionPipelineIfNeeded(retryAfterFailure: true)
                    }
                }
        }
    }
}

class AppState: ObservableObject {
    @Published var exploitStatus: ExploitStatus = .notStarted
    @Published var unsupportedMessage: String?
    @Published var kernelExploitRunning = false

    private var autoRunAttempted = false

    var kernelExploitApplicable: Bool {
        KernelExploit.isApplicable(
            major: AppInfo.versionTuple.major,
            minor: AppInfo.versionTuple.minor,
            patch: AppInfo.versionTuple.patch,
            build: AppInfo.osBuild
        )
    }

    var isSupported: Bool { unsupportedMessage == nil }

    func detectSupport() {
        let v = AppInfo.versionTuple
        let supported = ExploitSupportPolicy.isSupported(
            major: v.major,
            minor: v.minor,
            patch: v.patch,
            build: AppInfo.osBuild
        )
#if targetEnvironment(simulator)
        if ProcessInfo.processInfo.arguments.contains("--simulate-access") {
            exploitStatus = .success(method: "Simulator preview")
        }
#endif

        unsupportedMessage = supported ? nil : "iOS \(AppInfo.osVersion) (\(AppInfo.osBuild))"
        if let unsupportedMessage {
            exploitStatus = .unsupported(unsupportedMessage)
            return
        }

        let applicable = KernelExploit.isApplicable(
            major: v.major,
            minor: v.minor,
            patch: v.patch,
            build: AppInfo.osBuild
        )
        guard applicable else { return }

        refreshKernelExploitStatus()
        maybeAutoRunKernelExploit()
    }

    private func maybeAutoRunKernelExploit() {
        guard !kernelExploitRunning,
              !exploitStatus.isSuccess,
              !exploitStatus.isFailed,
              !autoRunAttempted else { return }
        autoRunAttempted = true
        log("app: starting kernel exploit automatically")
        runKernelExploitIfNeeded()
    }

    private func refreshKernelExploitStatus() {
        guard !kernelExploitRunning else { return }

        // iOS < 26: kernel R/W success persists (no sandbox probe)
        // iOS >= 26: verify full sandbox escape is still active
        if KernelExploit.requiresSandboxEscape {
            if KernelExploit.hasSandboxAccess() {
                if !exploitStatus.isSuccess {
                    exploitStatus = .success(method: "kexploit")
                    log("app: existing sandbox access is still active; skipping kernel exploit")
                }
            } else if exploitStatus.isSuccess {
                exploitStatus = .notStarted
                log("app: sandbox access is no longer active")
            }
        }
    }

    func runKernelExploitIfNeeded() {
        refreshKernelExploitStatus()
        guard !kernelExploitRunning,
              !exploitStatus.isSuccess,
              !exploitStatus.isFailed else { return }
        kernelExploitRunning = true
        exploitStatus = .notStarted
        log("app: running kernel exploit on background...")
        DispatchQueue.global(qos: .userInitiated).async {
            let ok = KernelExploit.run()
            DispatchQueue.main.async {
                self.kernelExploitRunning = false
                if ok {
                    self.exploitStatus = .success(method: "kexploit")
                    if KernelExploit.requiresSandboxEscape {
                        log("app: kernel exploit success — sandbox access verified")
                    } else {
                        log("app: kernel exploit success — kernel access active")
                    }
                } else {
                    self.exploitStatus = .failed(method: "kexploit", code: -1)
                    log("app: kernel exploit failed — relaunch the app before retrying")
                }
            }
        }
    }
}
