import Foundation

final class EventPipeline {
    private let queue = DispatchQueue(label: "dynamictool.event-pipeline")
    private let writer: JSONLWriter

    init(writer: JSONLWriter) {
        self.writer = writer
    }

    func accept(_ event: Event) {
        queue.async { [self] in
            write(event)
        }
    }

    private func write(_ event: Event) {
        do {
            try writer.append(event)
        } catch {
            FileHandle.standardError.write(Data("writer error: \(error)\n".utf8))
        }
    }

    func flushAndClose() throws {
        var closeError: Error?
        queue.sync {
            do {
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
