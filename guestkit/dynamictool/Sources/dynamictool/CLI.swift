import Foundation

struct RunConfig {
    let executable: String
    let arguments: [String]
    let outputPath: String
    let dtraceScript: String?
}

enum Command {
    case run(RunConfig)
}

enum CLI {
    static func parse(_ arguments: [String]) throws -> Command {
        var cursor = ArgumentCursor(arguments)

        guard let command = cursor.next() else {
            throw AnalyzerError.usage(usage)
        }

        switch command {
        case "run":
            return .run(try parseRun(&cursor))
        case "-h", "--help", "help":
            throw AnalyzerError.usage(usage)
        default:
            throw AnalyzerError.usage("unknown command: \(command)\n\(usage)")
        }
    }

    private static func parseRun(_ cursor: inout ArgumentCursor) throws -> RunConfig {
        var outputPath: String?
        var dtraceScript: String?

        parseOptions: while let arg = cursor.peek() {
            switch arg {
            case "-o", "--output":
                _ = cursor.next()
                outputPath = try cursor.requireValue(for: arg)
            case "-ds", "--dtrace-script":
                _ = cursor.next()
                dtraceScript = try cursor.requireValue(for: arg)
            case "--":
                _ = cursor.next()
                break parseOptions
            default:
                if !arg.hasPrefix("-") {
                    break parseOptions
                }
                _ = cursor.next()
                throw AnalyzerError.usage("unknown option: \(arg)\n\(usage)")
            }
        }

        guard let executable = cursor.next() else {
            throw AnalyzerError.usage(usage)
        }

        return RunConfig(
            executable: executable,
            arguments: cursor.remaining(),
            outputPath: outputPath ?? "-",
            dtraceScript: dtraceScript
        )
    }

    static let usage = """
        usage:
          dynamictool run [-o output.jsonl] [--dtrace-script script.d] executable [arguments...]
          dynamictool run [-o output.jsonl] [--dtrace-script script.d] -- executable [arguments...]
        """
}

private struct ArgumentCursor {
    private var arguments: ArraySlice<String>

    init(_ arguments: [String]) {
        self.arguments = ArraySlice(arguments)
    }

    func peek() -> String? {
        arguments.first
    }

    mutating func next() -> String? {
        arguments.popFirst()
    }

    mutating func requireValue(for option: String) throws -> String {
        guard let value = next(), !value.isEmpty else {
            throw AnalyzerError.usage("missing value for \(option)\n\(CLI.usage)")
        }
        return value
    }

    func remaining() -> [String] {
        Array(arguments)
    }
}
