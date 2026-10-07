import Darwin
import Foundation

final class JSONLWriter {
    private let handle: FileHandle
    private let encoder: JSONEncoder
    private let shouldClose: Bool
    private var buffer = Data()
    private var isClosed = false

    /// Flush to disk once the in-memory buffer reaches this size.
    private let flushThreshold = 64 * 1024

    init(path: String) throws {
        encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.withoutEscapingSlashes]

        if path == "-" {
            handle = .standardOutput
            shouldClose = false
            return
        }

        let url = URL(fileURLWithPath: path).standardizedFileURL
        let directory = url.deletingLastPathComponent()
        if directory.path != "." && !directory.path.isEmpty {
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true)
        }

        // Fresh file per run; CLOEXEC so sample children don't inherit the fd.
        let fd = open(url.path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0o644)
        guard fd >= 0 else {
            throw AnalyzerError.fileWrite(
                "failed to open output file \(url.path): \(String(cString: strerror(errno)))")
        }
        // We own the fd and close it explicitly in close().
        handle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        shouldClose = true
    }

    func append(_ event: Event) throws {
        guard !isClosed else {
            throw AnalyzerError.fileWrite("write to closed JSONLWriter")
        }

        var line = try encoder.encode(event)
        line.append(0x0a)
        buffer.append(line)

        if buffer.count >= flushThreshold {
            try flushBuffer()
        }
    }

    func flush() throws {
        guard !isClosed else { return }
        try flushBuffer()
        if shouldClose {
            try handle.synchronize()
        }
    }

    func close() throws {
        guard !isClosed else { return }
        try flushBuffer()
        isClosed = true
        guard shouldClose else { return }
        try handle.synchronize()
        try handle.close()
    }

    private func flushBuffer() throws {
        guard !buffer.isEmpty else { return }
        do {
            try handle.write(contentsOf: buffer)
        } catch {
            throw AnalyzerError.fileWrite("JSONL write failed: \(error.localizedDescription)")
        }
        buffer.removeAll(keepingCapacity: true)
    }
}
