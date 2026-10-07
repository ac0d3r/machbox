import Foundation

final class DTraceClient {
    private let scriptPath: String
    private let sink: (Event) -> Void
    private var process: Process?
    private var pipeHandle: FileHandle?
    private var buffer = ""
    private let queue = DispatchQueue(label: "dynamictool.dtrace")
    private let readySemaphore = DispatchSemaphore(value: 0)
    private var isReady = false

    private static let regex: NSRegularExpression = {
        try! NSRegularExpression(pattern: #"(\w+)=([^ ]+)"#, options: [])
    }()

    init(scriptPath: String, sink: @escaping (Event) -> Void) {
        self.scriptPath = scriptPath
        self.sink = sink
    }

    func start() throws {
        guard FileManager.default.fileExists(atPath: scriptPath) else {
            throw AnalyzerError.usage("dtrace script not found: \(scriptPath)")
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/dtrace")
        process.arguments = ["-C", "-s", scriptPath]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        let handle = pipe.fileHandleForReading
        self.pipeHandle = handle
        handle.readabilityHandler = { [weak self] handle in
            guard let self else { return }
            let data = handle.availableData
            guard !data.isEmpty else {
                self.flushBuffer()
                return
            }
            guard let text = String(data: data, encoding: .utf8) else { return }
            self.consume(text)
        }

        process.terminationHandler = { [weak self] _ in
            self?.flushBuffer()
        }

        try process.run()
        self.process = process
    }

    func stop() {
        queue.sync {
            if let process = self.process {
                process.terminate()
                process.waitUntilExit()
            }
            self.process = nil

            self.pipeHandle?.readabilityHandler = nil
            self.pipeHandle?.closeFile()
            self.pipeHandle = nil

            self._flushBuffer()
        }
    }

    // MARK: - Buffer handling (always dispatched to queue)

    private func consume(_ text: String) {
        queue.async { [weak self] in
            guard let self else { return }
            self.buffer += text
            while let newlineIndex = self.buffer.firstIndex(of: "\n") {
                let line = String(self.buffer[..<newlineIndex])
                let afterNewline = self.buffer.index(after: newlineIndex)
                self.buffer = String(self.buffer[afterNewline...])
                self.processLine(line)
            }
        }
    }

    private func flushBuffer() {
        queue.async { [weak self] in
            self?._flushBuffer()
        }
    }

    private func _flushBuffer() {
        if !buffer.isEmpty {
            let line = buffer
            buffer = ""
            processLine(line)
        }
    }

    private func processLine(_ line: String) {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        if trimmed == "PROBE_START" {
            queue.async { [weak self] in
                guard let self else { return }
                if !self.isReady {
                    self.isReady = true
                    self.readySemaphore.signal()
                }
            }
            return
        }
        if let event = Self.parse(line: trimmed) {
            sink(event)
        }
    }

    func waitForReady(timeout: TimeInterval) -> Bool {
        let result = readySemaphore.wait(timeout: .now() + timeout)
        return result == .success
    }

    // MARK: - Factory

    static func maybeStart(
        scriptPath: String, sink: @escaping (Event) -> Void, readyTimeout: TimeInterval = 5
    ) -> DTraceClient? {
        do {
            let client = DTraceClient(scriptPath: scriptPath, sink: sink)
            try client.start()
            FileHandle.standardError.write(
                Data("dynamictool: dtrace network probe started (\(scriptPath))\n".utf8))
            if client.waitForReady(timeout: readyTimeout) {
                FileHandle.standardError.write(
                    Data("dynamictool: dtrace network probe ready\n".utf8))
            } else {
                FileHandle.standardError.write(
                    Data("dynamictool: warning: dtrace network probe ready timeout\n".utf8))
            }
            return client
        } catch {
            FileHandle.standardError.write(
                Data("dynamictool: warning: failed to start dtrace network probe: \(error)\n".utf8))
            return nil
        }
    }

    // MARK: - Parsing

    private static func parse(line: String) -> Event? {
        var dict: [String: String] = [:]
        let range = NSRange(line.startIndex..., in: line)
        regex.enumerateMatches(in: line, options: [], range: range) { match, _, _ in
            guard let match = match, match.numberOfRanges == 3 else { return }
            if let keyRange = Range(match.range(at: 1), in: line),
                let valueRange = Range(match.range(at: 2), in: line)
            {
                dict[String(line[keyRange])] = String(line[valueRange])
            }
        }

        guard let tsStr = dict["ts"],
            let type = dict["type"],
            let pidStr = dict["pid"],
            let tsVal = TimeInterval(tsStr),
            let pid = Int32(pidStr)
        else {
            return nil
        }

        let ts = Date(timeIntervalSince1970: tsVal)
        let comm = dict["comm"]

        var target: String?
        var metadata: [String: String] = [:]

        if let family = dict["family"] {
            metadata["family"] = family
        }
        if let dir = dict["dir"] {
            metadata["direction"] = dir
        }
        if let local = dict["local"] {
            target = local
            metadata["local"] = local
        }
        if let remote = dict["remote"] {
            target = remote
            metadata["remote"] = remote
        }
        if let path: String = dict["path"] {
            target = path
            metadata["path"] = path
        }

        return Event(
            ts: ts,
            type: type,
            pid: pid,
            ppid: nil,
            process: comm,
            target: target,
            metadata: metadata.isEmpty ? nil : metadata
        )
    }
}
