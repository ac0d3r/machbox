import Foundation

final class EventPipeline {
    private let queue = DispatchQueue(label: "dynamictool.event-pipeline")
    private let writer: JSONLWriter
    private var isClosed = false

    init(writer: JSONLWriter) {
        self.writer = writer
    }

    func accept(_ event: Event) {
        queue.async { [self] in
            guard !isClosed else { return }
            do {
                try writer.append(event)
            } catch {
                FileHandle.standardError.write(Data("writer error: \(error)\n".utf8))
            }
        }
    }

    func flushAndClose() throws {
        var closeError: Error?
        queue.sync {
            guard !isClosed else { return }
            isClosed = true
            do {
                try writer.flush()
                try writer.close()
            } catch {
                closeError = error
            }
        }
        if let closeError {
            throw closeError
        }
    }
}
