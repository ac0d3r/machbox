import Foundation

struct ProcessIdentity: Codable {
    let pid: pid_t
    let pidversion: Int32?
    let ppid: pid_t?
    let ppidversion: Int32?
    let path: String?
}

struct EventObject: Codable {
    let kind: String
    let path: String?
    let pid: pid_t?
    let pidversion: Int32?
    let ppid: pid_t?
    let ppidversion: Int32?
    let name: String?

    init(
        kind: String,
        path: String? = nil,
        pid: pid_t? = nil,
        pidversion: Int32? = nil,
        ppid: pid_t? = nil,
        ppidversion: Int32? = nil,
        name: String? = nil
    ) {
        self.kind = kind
        self.path = path
        self.pid = pid
        self.pidversion = pidversion
        self.ppid = ppid
        self.ppidversion = ppidversion
        self.name = name
    }
}

struct Event: Codable {
    let ts: Date
    let type: String
    let pid: pid_t
    let pidversion: Int32?
    let ppid: pid_t?
    let ppidversion: Int32?
    let process: String?
    let target: String?
    let subject: ProcessIdentity?
    let object: EventObject?
    let metadata: [String: String]?

    init(
        ts: Date,
        type: String,
        pid: pid_t,
        pidversion: Int32? = nil,
        ppid: pid_t?,
        ppidversion: Int32? = nil,
        process: String?,
        target: String?,
        subject: ProcessIdentity? = nil,
        object: EventObject? = nil,
        metadata: [String: String]? = nil
    ) {
        self.ts = ts
        self.type = type
        self.pid = pid
        self.pidversion = pidversion
        self.ppid = ppid
        self.ppidversion = ppidversion
        self.process = process
        self.target = target
        self.subject = subject
        self.object = object
        self.metadata = metadata
    }
}

enum AnalyzerError: Error, CustomStringConvertible {
    case usage(String)
    case endpointSecurity(String)
    case fileWrite(String)
    case launch(String)

    var description: String {
        switch self {
        case .usage(let message),
            .endpointSecurity(let message),
            .fileWrite(let message),
            .launch(let message):
            return message
        }
    }
}
