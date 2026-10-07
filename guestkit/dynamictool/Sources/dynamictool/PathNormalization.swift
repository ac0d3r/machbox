import Foundation

enum PathNormalization {
    static func normalize(_ path: String) -> String {
        if path.hasPrefix("/private/var/") {
            return "/var/" + path.dropFirst("/private/var/".count)
        }
        if path.hasPrefix("/private/tmp/") {
            return "/tmp/" + path.dropFirst("/private/tmp/".count)
        }
        return path
    }

    static func matches(_ lhs: String?, _ rhs: String) -> Bool {
        guard let lhs, !lhs.isEmpty else { return false }
        return normalize(lhs) == normalize(rhs)
    }

    /// `/var/foo` ↔ `/private/var/foo` (and the same for `/tmp`).
    static func equivalentPaths(_ path: String) -> [String] {
        let normalized = normalize(path)
        if normalized.hasPrefix("/var/") {
            return Array(Set([normalized, "/private" + normalized]))
        }
        if normalized.hasPrefix("/tmp/") {
            return Array(Set([normalized, "/private" + normalized]))
        }
        if path != normalized {
            return Array(Set([path, normalized]))
        }
        return [path]
    }
}
