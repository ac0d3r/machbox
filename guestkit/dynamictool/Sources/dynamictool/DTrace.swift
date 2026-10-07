import Darwin
import Foundation

final class DTraceClient {
    private let scriptPath: String
    private let targetPid: pid_t
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

    init(scriptPath: String, targetPid: pid_t, sink: @escaping (Event) -> Void) {
        self.scriptPath = scriptPath
        self.targetPid = targetPid
        self.sink = sink
    }

    func start() throws {
        guard FileManager.default.fileExists(atPath: scriptPath) else {
            throw AnalyzerError.usage("dtrace script not found: \(scriptPath)")
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/dtrace")
        // -D must come before -s so the preprocessor sees TARGET_PID.
        process.arguments = [
            "-C",
            "-D", "TARGET_PID=\(targetPid)",
            "-s", scriptPath,
        ]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        let handle = pipe.fileHandleForReading
        self.pipeHandle = handle
        handle.readabilityHandler = { [weak self] handle in
            guard let self else { return }
            let data = handle.availableData
            guard !data.isEmpty else {
                self.flushBufferAsync()
                return
            }
            guard let text = String(data: data, encoding: .utf8) else { return }
            self.consume(text)
        }

        process.terminationHandler = { [weak self] _ in
            self?.flushBufferAsync()
        }

        try process.run()
        self.process = process
    }

    func stop() {
        // Drop the handler before tearing down the process to avoid races.
        pipeHandle?.readabilityHandler = nil

        queue.sync {
            if let process = self.process {
                process.terminate()
                process.waitUntilExit()
            }
            self.process = nil
            self.pipeHandle?.closeFile()
            self.pipeHandle = nil
            self.flushBufferLocked()
        }
    }

    func waitForReady(timeout: TimeInterval) -> Bool {
        readySemaphore.wait(timeout: .now() + timeout) == .success
    }

    // MARK: - Factory

    static func maybeStart(
        scriptPath: String,
        targetPid: pid_t,
        sink: @escaping (Event) -> Void,
        readyTimeout: TimeInterval = 5
    ) -> DTraceClient? {
        do {
            let client = DTraceClient(
                scriptPath: scriptPath, targetPid: targetPid, sink: sink)
            try client.start()
            FileHandle.standardError.write(
                Data(
                    "dynamictool: dtrace network probe started (pid=\(targetPid) script=\(scriptPath))\n"
                        .utf8))
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

    // MARK: - Buffer handling

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

    private func flushBufferAsync() {
        queue.async { [weak self] in
            self?.flushBufferLocked()
        }
    }

    private func flushBufferLocked() {
        guard !buffer.isEmpty else { return }
        let line = buffer
        buffer = ""
        processLine(line)
    }

    private func processLine(_ line: String) {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        if trimmed == "PROBE_START" {
            if !isReady {
                isReady = true
                readySemaphore.signal()
            }
            return
        }
        if let event = Self.parse(line: trimmed) {
            sink(event)
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

        var metadata: [String: String] = [:]
        for key in ["family", "dir", "local", "remote", "path", "socktype", "protocol"] {
            if let value = dict[key], !value.isEmpty {
                metadata[key == "dir" ? "direction" : key] = value
            }
        }

        let target = dict["remote"] ?? dict["local"] ?? dict["path"]
        let process = processPath(for: pid) ?? dict["comm"]

        return Event(
            ts: Date(timeIntervalSince1970: tsVal),
            type: type,
            pid: pid,
            ppid: nil,
            process: process,
            target: target,
            metadata: metadata.isEmpty ? nil : metadata
        )
    }

    private static func processPath(for pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        return String(cString: buffer)
    }
}
