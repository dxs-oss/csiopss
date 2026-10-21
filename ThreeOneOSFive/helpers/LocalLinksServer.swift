import Foundation
import Darwin

/// 极简本地 HTTP 服务器（方案 B）：
/// 对任意路径的任意请求，都返回同一个 200 响应，body = links.txt 的内容。
///
/// 配合补丁后的 apptrace（请求地址 = http://127.0.0.1:8888）使用：
/// 二进制第一次"请求"变成访问本机回环，拿到的 body 就是服务端本应返回的
/// 密文响应体，之后照常 base64→AES 解密→拿到链接→直接请求。
///
/// 本版本改动：
///  1. 记录每条请求的 方法/路径 与返回字节数（用于定位 8888 是否被请求、响应是否送达）；
///  2. 先完整读完请求再响应，避免 close 时存在未读数据触发 TCP RST 把响应冲掉；
///  3. 发送用 sendAll 循环，防止部分发送。
final class LocalLinksServer {
    static let shared = LocalLinksServer()

    private var serverFD: Int32 = -1
    private var body = Data()
    private var connectionCount = 0
    private var heartbeatTask: DispatchWorkItem?

    private init() {}

    /// - Parameters:
    ///   - port: 监听端口，默认 8888（与补丁后的 URL 保持一致）
    ///   - responseFile: 响应体文件（links.txt，内容是真实服务端响应密文）
    func start(port: UInt16 = 8888, responseFile: URL) {
        guard serverFD < 0 else { return }
        body = (try? Data(contentsOf: responseFile)) ?? Data()
        guard !body.isEmpty else {
            log("LocalLinksServer: links.txt 为空或不存在，服务器不启动")
            return
        }
        log("LocalLinksServer: loaded \(body.count) bytes from links.txt")

        serverFD = socket(AF_INET, SOCK_STREAM, 0)
        guard serverFD >= 0 else { return }

        var yes: Int32 = 1
        setsockopt(serverFD, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(serverFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0, listen(serverFD, 16) == 0 else {
            close(serverFD)
            serverFD = -1
            log("LocalLinksServer: bind/listen failed on 127.0.0.1:\(port)")
            return
        }
        log("LocalLinksServer: listening on 127.0.0.1:\(port)")
        DispatchQueue.global(qos: .background).async { [weak self] in
            self?.acceptLoop()
        }
        // 自检探针：0.5 秒后用 App 自身访问回环服务，验证进程内 loopback 是否可用
        DispatchQueue.global(qos: .background).asyncAfter(deadline: .now() + 0.5) { [weak self] in
            self?.runSelfProbe(port: port)
        }
        // 心跳：每 20 秒记录一次服务器状态，便于确认服务器一直存活、期间是否收到过连接
        var heartbeat: DispatchWorkItem!
        heartbeat = DispatchWorkItem { [weak self] in
            guard let self, self.serverFD >= 0 else { return }
            log("LocalLinksServer: heartbeat alive — connections so far: \(self.connectionCount)")
            DispatchQueue.global(qos: .background).asyncAfter(deadline: .now() + 20, execute: heartbeat)
        }
        heartbeatTask = heartbeat
        DispatchQueue.global(qos: .background).asyncAfter(deadline: .now() + 20, execute: heartbeat)
    }

    private func runSelfProbe(port: UInt16) {
        guard let url = URL(string: "http://127.0.0.1:\(port)/__probe") else { return }
        URLSession.shared.dataTask(with: url) { data, resp, err in
            let code = (resp as? HTTPURLResponse)?.statusCode ?? -1
            log("LocalLinksServer: self-probe status=\(code) bytes=\(data?.count ?? 0) err=\(err?.localizedDescription ?? "nil")")
        }.resume()
    }

    func stop() {
        guard serverFD >= 0 else { return }
        close(serverFD)
        serverFD = -1
    }

    private func acceptLoop() {
        while serverFD >= 0 {
            let client = accept(serverFD, nil, nil)
            guard client >= 0 else { continue }
            connectionCount += 1
            log("LocalLinksServer: conn accepted (fd=\(client), total=\(connectionCount))")
            DispatchQueue.global(qos: .background).async { [weak self] in
                self?.handle(client)
            }
        }
    }

    private func handle(_ fd: Int32) {
        defer { close(fd) }

        // 2 秒读超时：先读完整个请求（读到空行即认为请求头已收全），
        // 避免响应后立刻 close 因内核缓冲区还有未读数据而发 RST。
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var request = [UInt8]()
        var buf = [UInt8](repeating: 0, count: 4096)
        while request.count < 65536 {
            let n = buf.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return recv(fd, base, raw.count, 0)
            }
            if n <= 0 { break }
            request.append(contentsOf: buf[0..<n])
            if request.firstRange(of: [0x0D, 0x0A, 0x0D, 0x0A]) != nil { break }
        }

        let firstLine = String(bytes: request.prefix(120), encoding: .utf8)?
            .components(separatedBy: "\r\n").first ?? "<non-text>"
        let hexPrefix = request.prefix(64).map { String(format: "%02x", $0) }.joined()
        log("LocalLinksServer: req \(firstLine) — got \(request.count)B hex=\(hexPrefix) — serving \(body.count) bytes")

        var response = Data()
        let header = "HTTP/1.1 200 OK\r\n"
            + "Content-Type: text/plain\r\n"
            + "Content-Length: \(body.count)\r\n"
            + "Connection: close\r\n\r\n"
        response.append(header.data(using: .utf8) ?? Data())
        response.append(body)

        response.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var sent = 0
            while sent < response.count {
                let n = send(fd, base.advanced(by: sent), response.count - sent, 0)
                if n <= 0 { break }
                sent += n
            }
            log("LocalLinksServer: sent \(sent)/\(response.count) bytes")
        }
    }
}
