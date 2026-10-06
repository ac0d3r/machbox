import Darwin
import Foundation

final class JSONLWriter {
    private let handle: FileHandle
    private let encoder: JSONEncoder
    private let shouldClose: Bool
    private var isClosed = false

    init(path: String) throws {
        if path == "-" {
            handle = FileHandle.standardOutput
            shouldClose = false
        } else {
            let url = URL(fileURLWithPath: path)
            let directory = url.deletingLastPathComponent()
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true)

            if !FileManager.default.fileExists(atPath: url.path) {
                guard FileManager.default.createFile(atPath: url.path, contents: nil) else {
                    throw AnalyzerError.fileWrite("failed to create output file: \(url.path)")
                }
            }

            handle = try FileHandle(forWritingTo: url)
            try Self.setCloseOnExec(handle.fileDescriptor, path: url.path)
            try handle.seekToEnd()
            shouldClose = true
        }

        encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.withoutEscapingSlashes]
    }

    func append(_ event: Event) throws {
        var data = try encoder.encode(event)
        data.append(0x0a)
        try handle.write(contentsOf: data)
    }

    func close() throws {
        guard shouldClose, !isClosed else { return }
        isClosed = true
        try handle.synchronize()
        try handle.close()
    }

    private static func setCloseOnExec(_ fd: Int32, path: String) throws {
        let flags = fcntl(fd, F_GETFD)
        guard flags >= 0 else {
            throw AnalyzerError.fileWrite(
                "fcntl(F_GETFD) failed for \(path): \(String(cString: strerror(errno)))")
        }

        let result = fcntl(fd, F_SETFD, flags | FD_CLOEXEC)
        guard result >= 0 else {
            throw AnalyzerError.fileWrite(
                "fcntl(F_SETFD, FD_CLOEXEC) failed for \(path): \(String(cString: strerror(errno)))"
            )
        }
    }
}
