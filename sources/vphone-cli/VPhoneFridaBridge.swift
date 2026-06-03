import Foundation
import Network
import Virtualization

/// Bridges Frida's barebone backend to the in-guest Frida agent over vsock.
///
/// Two channels are exposed:
/// - **GDB**: outbound to guest port 1338 (the kernel-resident loader stub).
///   Surfaced as a local TCP listener on 127.0.0.1 so frida-core's
///   `connection: { host, port }` config can point at it.
/// - **Hostlink**: inbound on host vsock port 1339 (the agent connects out
///   from kernel space). Surfaced as a UNIX socket so frida-core's
///   `VsockTransportConfig.socket_path` can point at it.
///
/// Endpoints are printed at attach time; the caller is responsible for
/// composing their own `FRIDA_BAREBONE_CONFIG`.
@MainActor
final class VPhoneFridaBridge: NSObject {
    static let loaderVsockPort: UInt32 = 1338
    static let agentVsockPort: UInt32 = 1339

    let hostlinkSocketPath: String
    private(set) var gdbHost = "127.0.0.1"
    private(set) var gdbPort: UInt16 = 0

    private weak var device: VZVirtioSocketDevice?
    private var gdbListener: NWListener?
    private var agentListener: VZVirtioSocketListener?
    private var agentListenerDelegate: AgentListenerDelegate?

    override init() {
        self.hostlinkSocketPath = FileManager.default.temporaryDirectory
            .appendingPathComponent("vphone-frida-\(getpid()).sock").path
        super.init()
    }

    func attach(to device: VZVirtioSocketDevice) throws {
        self.device = device
        try startGDBProxy()
        try startAgentProxy(on: device)
        print("[frida] hostlink socket: \(hostlinkSocketPath)")
        print("[frida] agent.transport: { type: vsock, socket_path: \(hostlinkSocketPath), port: \(Self.agentVsockPort) }")
    }

    func detach() {
        gdbListener?.cancel()
        gdbListener = nil
        if let device {
            device.removeSocketListener(forPort: Self.agentVsockPort)
        }
        agentListener = nil
        agentListenerDelegate = nil
        try? FileManager.default.removeItem(atPath: hostlinkSocketPath)
    }

    private func startGDBProxy() throws {
        let listener = try NWListener(using: .tcp, on: .any)
        listener.newConnectionHandler = { [weak self] inbound in
            Task { @MainActor in self?.proxyGDB(inbound: inbound) }
        }
        listener.stateUpdateHandler = { [weak self] state in
            if case .ready = state, let port = listener.port {
                Task { @MainActor in self?.recordGDBPort(port.rawValue) }
            }
        }
        listener.start(queue: .main)
        gdbListener = listener
    }

    private func proxyGDB(inbound: NWConnection) {
        guard let device else { inbound.cancel(); return }
        device.connect(toPort: Self.loaderVsockPort) { (result: Result<VZVirtioSocketConnection, any Error>) in
            switch result {
            case .failure(let error):
                print("[frida] vsock connect to loader failed: \(error)")
                inbound.cancel()
            case .success(let vsock):
                Self.spliceBytes(tcp: inbound, vsock: vsock)
            }
        }
    }

    private func startAgentProxy(on device: VZVirtioSocketDevice) throws {
        let listener = VZVirtioSocketListener()
        let delegate = AgentListenerDelegate(socketPath: hostlinkSocketPath)
        agentListenerDelegate = delegate
        listener.delegate = delegate
        device.setSocketListener(listener, forPort: Self.agentVsockPort)
        agentListener = listener
    }

    private func recordGDBPort(_ port: UInt16) {
        gdbPort = port
        print("[frida] gdb stub bridged at \(gdbHost):\(port)  →  vsock:\(Self.loaderVsockPort)")
    }

    nonisolated private static func spliceBytes(tcp: NWConnection, vsock: VZVirtioSocketConnection) {
        let fd = Darwin.dup(vsock.fileDescriptor)
        guard fd >= 0 else { tcp.cancel(); return }
        let queue = DispatchQueue(label: "frida.gdb.proxy")
        tcp.start(queue: queue)
        pumpVsockToTCP(fd: fd, tcp: tcp)
        pumpTCPToVsock(tcp: tcp, fd: fd)
    }

    nonisolated private static func pumpVsockToTCP(fd: Int32, tcp: NWConnection) {
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: .global())
        source.setEventHandler {
            var buf = [UInt8](repeating: 0, count: 4096)
            let n = read(fd, &buf, buf.count)
            if n <= 0 { tcp.cancel(); source.cancel(); return }
            tcp.send(content: Data(buf[..<n]), completion: .contentProcessed { _ in })
        }
        source.resume()
    }

    nonisolated private static func pumpTCPToVsock(tcp: NWConnection, fd: Int32) {
        tcp.receive(minimumIncompleteLength: 1, maximumLength: 4096) { @Sendable data, _, isComplete, error in
            if let data, !data.isEmpty {
                data.withUnsafeBytes { ptr in
                    _ = write(fd, ptr.baseAddress, data.count)
                }
            }
            if isComplete || error != nil { close(fd); return }
            pumpTCPToVsock(tcp: tcp, fd: fd)
        }
    }
}

private final class AgentListenerDelegate: NSObject, VZVirtioSocketListenerDelegate, @unchecked Sendable {
    let socketPath: String

    init(socketPath: String) {
        self.socketPath = socketPath
        super.init()
    }

    nonisolated func listener(
        _ listener: VZVirtioSocketListener,
        shouldAcceptNewConnection connection: VZVirtioSocketConnection,
        from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
        let vsockFD = Darwin.dup(connection.fileDescriptor)
        if vsockFD >= 0 {
            bridgeToUnixSocket(vsockFD: vsockFD, socketPath: socketPath)
        }
        return true
    }
}

private func bridgeToUnixSocket(vsockFD: Int32, socketPath: String) {
    DispatchQueue.global().async {
        try? FileManager.default.removeItem(atPath: socketPath)
        let listenFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listenFD >= 0 else { close(vsockFD); return }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathCapacity = MemoryLayout.size(ofValue: addr.sun_path)
        let pathBytes = Array(socketPath.utf8CString)
        withUnsafeMutablePointer(to: &addr.sun_path) { dstTuple in
            dstTuple.withMemoryRebound(to: CChar.self, capacity: pathCapacity) { dst in
                let n = min(pathBytes.count, pathCapacity - 1)
                for i in 0..<n { dst[i] = pathBytes[i] }
                dst[n] = 0
            }
        }
        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bindRC = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listenFD, $0, addrLen) }
        }
        guard bindRC == 0, listen(listenFD, 1) == 0 else { close(listenFD); close(vsockFD); return }

        let acceptedFD = accept(listenFD, nil, nil)
        close(listenFD)
        guard acceptedFD >= 0 else { close(vsockFD); return }

        spliceFDs(acceptedFD, vsockFD)
    }
}

private func spliceFDs(_ a: Int32, _ b: Int32) {
    pumpOneWay(a, b)
    pumpOneWay(b, a)
}

private func pumpOneWay(_ src: Int32, _ dst: Int32) {
    let source = DispatchSource.makeReadSource(fileDescriptor: src, queue: .global())
    source.setEventHandler {
        var buf = [UInt8](repeating: 0, count: 4096)
        let n = read(src, &buf, buf.count)
        if n <= 0 { close(src); close(dst); source.cancel(); return }
        // `&buf[off]` only yields a stable pointer to a single element; writing `n - off`
        // bytes from it streams adjacent stack garbage. Take a proper buffer pointer.
        let ok = buf.withUnsafeBytes { raw -> Bool in
            let base = raw.baseAddress!
            var off = 0
            while off < n {
                let w = write(dst, base + off, n - off)
                if w <= 0 { return false }
                off += w
            }
            return true
        }
        if !ok { close(src); close(dst); source.cancel(); return }
    }
    source.resume()
}
