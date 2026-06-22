import EndpointSecurity
import Foundation

final class EndpointSecurityClient {
    private var client: OpaquePointer?
    private let dispatchQueue = DispatchQueue(label: "dynamictool.es-events", qos: .userInitiated)
    private let sink: (Event) -> Void

    init(sink: @escaping (Event) -> Void) {
        self.sink = sink
    }

    func start() throws {
        let result = es_new_client(&client) { [weak self] _, message in
            guard let self, let event = Self.normalize(message: message) else {
                return
            }

            if Self.NoiseFilter.shouldDrop(event: event) {
                return
            }
            self.dispatchQueue.async {
                self.sink(event)
            }
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            throw AnalyzerError.endpointSecurity(Self.newClientErrorDescription(result))
        }

        muteSelfProcess()
        muteSystemProcesses()

        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_OPEN,
            ES_EVENT_TYPE_NOTIFY_CREATE,
            ES_EVENT_TYPE_NOTIFY_WRITE,
            ES_EVENT_TYPE_NOTIFY_CLOSE,
            ES_EVENT_TYPE_NOTIFY_RENAME,
            ES_EVENT_TYPE_NOTIFY_UNLINK,
            ES_EVENT_TYPE_NOTIFY_MMAP,
            ES_EVENT_TYPE_NOTIFY_UIPC_BIND,
            ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT,
            ES_EVENT_TYPE_NOTIFY_XPC_CONNECT,
            ES_EVENT_TYPE_NOTIFY_PROC_CHECK,
            ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME,
            ES_EVENT_TYPE_NOTIFY_TRACE,
            ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE,
            ES_EVENT_TYPE_NOTIFY_SIGNAL,
            ES_EVENT_TYPE_NOTIFY_SETUID,
            ES_EVENT_TYPE_NOTIFY_SETGID,
            ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
            ES_EVENT_TYPE_NOTIFY_GET_TASK,
            ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME,
            ES_EVENT_TYPE_NOTIFY_GET_TASK_READ,
            ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT,
            ES_EVENT_TYPE_NOTIFY_KEXTLOAD,
            ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD,
            ES_EVENT_TYPE_NOTIFY_MOUNT,
            ES_EVENT_TYPE_NOTIFY_UNMOUNT,
            ES_EVENT_TYPE_NOTIFY_REMOUNT,
            ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN,
            ES_EVENT_TYPE_NOTIFY_MPROTECT,
            ES_EVENT_TYPE_NOTIFY_LINK,
            ES_EVENT_TYPE_NOTIFY_SETEXTATTR,
            ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
            ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE,
            ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN,
            ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT,
            ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH,
            ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH,
            ES_EVENT_TYPE_NOTIFY_SETEUID,
            ES_EVENT_TYPE_NOTIFY_SETEGID,
            ES_EVENT_TYPE_NOTIFY_SETREUID,
            ES_EVENT_TYPE_NOTIFY_SETREGID,
        ]

        let subscribeResult = events.withUnsafeBufferPointer { buffer in
            es_subscribe(client!, buffer.baseAddress!, UInt32(buffer.count))
        }

        guard subscribeResult == ES_RETURN_SUCCESS else {
            throw AnalyzerError.endpointSecurity("es_subscribe failed")
        }
    }

    private func muteSelfProcess() {
        guard let client else { return }

        var token = audit_token_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size
        )
        let kr = withUnsafeMutablePointer(to: &token) {
            $0.withMemoryRebound(
                to: integer_t.self,
                capacity: Int(count)
            ) {
                task_info(
                    mach_task_self_,
                    task_flavor_t(TASK_AUDIT_TOKEN),
                    $0,
                    &count
                )
            }
        }

        guard kr == KERN_SUCCESS else {
            FileHandle.standardError.write(
                Data("dynamictool: warning: failed to get self audit token\n".utf8))
            return
        }
        withUnsafePointer(to: token) { ptr in
            let result = es_mute_process(client, ptr)
            if result != ES_RETURN_SUCCESS {
                FileHandle.standardError.write(
                    Data("dynamictool: warning: es_mute_process(self) failed\n".utf8))
            }
        }
    }

    private func muteSystemProcesses() {
        guard let client else { return }

        let paths: [String] = [
            "/usr/sbin/syslogd",
            "/usr/libexec/logd",
            "/usr/libexec/logd_helper",
            "/usr/sbin/notifyd",  // 通知守护
            "/usr/sbin/distnoted",  // 通知系统
            "/usr/sbin/cfprefsd",  // 偏好设置
            "/usr/sbin/automount",
            "/usr/libexec/coreservicesd",
            "/usr/libexec/biomed",
            "/usr/libexec/oahd",  // Rosetta
            "/usr/libexec/timed",  // 时间同步
            "/usr/libexec/powerd",  // 电源管理
            "/usr/libexec/gamepolicyd",  // 游戏策略
            "/usr/libexec/runningboardd",  // 进程生命周期管理
            "/usr/libexec/thermalmonitord",  // 温控服务
            "/usr/libexec/endpointsecurityd",  // ES 自身
            "/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer",  // 窗口服务器
            "/System/Library/PrivateFrameworks/EcosystemAnalytics.framework/Support/ecosystemanalyticsd",  // Apple Analytics
            // Metal Shader 编译
            "/System/Library/Frameworks/Metal.framework/Versions/A/XPCServices/MTLCompilerService.xpc/Contents/MacOS/MTLCompilerService",
            "/System/Library/Frameworks/Metal.framework/Versions/A/XPCServices/MTLCompilerService.xpc",
            // machbox
            "/usr/local/libexec/machbox-guest",
        ]

        for path in paths {
            let result = path.withCString { cPath in
                es_mute_path(client, cPath, ES_MUTE_PATH_TYPE_LITERAL)
            }
            if result != ES_RETURN_SUCCESS {
                FileHandle.standardError.write(
                    Data("dynamictool: warning: failed to ES-mute \(path)\n".utf8))
            }
        }
    }

    private enum NoiseFilter {
        static let noisyPathPrefixes: [String] = [
            // Spotlight
            "/System/Volumes/Data/.Spotlight-V100",
            "/.Spotlight-V100",
            "/private/var/db/Spotlight",
            // Biome
            "/private/var/db/biome",
            "/Library/Biome",
        ]
        static let noisyProcesses: Set<String> = [
            // Spotlight
            "System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared",
            "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mds",
            "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mds_stores",
            // Biome
            "/System/Library/PrivateFrameworks/BiomeStreams.framework/Support/BiomeAgent",
            // CoreDuet
            "/System/Library/PrivateFrameworks/CoreDuetContext.framework/Versions/A/Resources/contextstored",
        ]
        static let lowValueEvents: Set<String> = [
            "open",
            "close",
            "write",
            "mmap",
            "proc_check",
        ]
        static func shouldDrop(event: Event) -> Bool {
            guard let processPath = event.process else {
                return false
            }
            guard noisyProcesses.contains(processPath) else {
                return false
            }
            guard lowValueEvents.contains(event.type) else {
                return false
            }
            guard let target = event.target else {
                return false
            }
            return noisyPathPrefixes.contains {
                target.hasPrefix($0)
            }
        }
    }

    func stop() {
        if let client {
            _ = es_delete_client(client)
            self.client = nil
        }
    }

    private static func normalize(message: UnsafePointer<es_message_t>) -> Event? {
        let msg = message.pointee
        let process = msg.process.pointee
        let processPID = audit_token_to_pid(process.audit_token)
        let processPIDVersion = audit_token_to_pidversion(process.audit_token)
        let processParentPIDVersion = parentPIDVersion(for: process, messageVersion: msg.version)
        let processPath = path(for: process.executable)

        let timestamp = Date(
            timeIntervalSince1970: TimeInterval(msg.time.tv_sec) + TimeInterval(msg.time.tv_nsec)
                / 1_000_000_000
        )
        let subject = ProcessIdentity(
            pid: processPID,
            pidversion: processPIDVersion,
            ppid: process.ppid,
            ppidversion: processParentPIDVersion,
            path: processPath
        )

        func event(
            _ type: String,
            target: String?,
            object: EventObject? = nil,
            metadata: [String: String]? = nil
        ) -> Event {
            Event(
                ts: timestamp,
                type: type,
                pid: processPID,
                pidversion: processPIDVersion,
                ppid: process.ppid,
                ppidversion: processParentPIDVersion,
                process: processPath,
                target: target,
                subject: subject,
                object: object,
                metadata: nonEmpty(metadata)
            )
        }

        switch msg.event_type {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            let target = msg.event.exec.target.pointee
            let targetPID = audit_token_to_pid(target.audit_token)
            let targetPIDVersion = audit_token_to_pidversion(target.audit_token)
            let targetParentPIDVersion = parentPIDVersion(for: target, messageVersion: msg.version)
            let targetPath = path(for: target.executable)

            var meta: [String: String] = [
                "is_platform": String(target.is_platform_binary)
            ]
            // extra exec args
            var execEvent = msg.event.exec
            withUnsafePointer(to: &execEvent) { execPtr in
                let argCount = es_exec_arg_count(execPtr)
                var argv: [String] = []
                for i in 0..<argCount {
                    let token = es_exec_arg(execPtr, i)
                    argv.append(string(from: token))
                }
                meta["argv"] = argv.joined(separator: "\u{00}")
            }
            // extra exec evns
            withUnsafePointer(to: &execEvent) { execPtr in
                let envCount = es_exec_env_count(execPtr)
                var envs: [String] = []
                for i in 0..<envCount {
                    let token = es_exec_env(execPtr, i)
                    envs.append(string(from: token))
                }
                meta["env"] = envs.joined(separator: "\u{00}")
            }

            return Event(
                ts: timestamp,
                type: "exec",
                pid: targetPID,
                pidversion: targetPIDVersion,
                ppid: target.ppid,
                ppidversion: targetParentPIDVersion,
                process: processPath,
                target: targetPath,
                subject: subject,
                object: EventObject(
                    kind: "process",
                    path: targetPath,
                    pid: targetPID,
                    pidversion: targetPIDVersion,
                    ppid: target.ppid,
                    ppidversion: targetParentPIDVersion
                ),
                metadata: nonEmpty(meta)
            )

        case ES_EVENT_TYPE_NOTIFY_FORK:
            let child = msg.event.fork.child.pointee
            let childPID = audit_token_to_pid(child.audit_token)
            let childPIDVersion = audit_token_to_pidversion(child.audit_token)
            let childPath = path(for: child.executable)
            return Event(
                ts: timestamp,
                type: "fork",
                pid: childPID,
                pidversion: childPIDVersion,
                ppid: processPID,
                ppidversion: processPIDVersion,
                process: processPath,
                target: childPath,
                subject: subject,
                object: EventObject(
                    kind: "process",
                    path: childPath,
                    pid: childPID,
                    pidversion: childPIDVersion,
                    ppid: processPID,
                    ppidversion: processPIDVersion
                )
            )

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            let exitStatus = msg.event.exit.stat
            return Event(
                ts: timestamp,
                type: "exit",
                pid: processPID,
                pidversion: processPIDVersion,
                ppid: process.ppid,
                ppidversion: processParentPIDVersion,
                process: processPath,
                target: nil,
                subject: subject,
                metadata: ["status": String(exitStatus)]
            )

        case ES_EVENT_TYPE_NOTIFY_OPEN:
            let target = path(for: msg.event.open.file)
            return Event(
                ts: timestamp,
                type: "open",
                pid: processPID,
                pidversion: processPIDVersion,
                ppid: process.ppid,
                ppidversion: processParentPIDVersion,
                process: processPath,
                target: target,
                subject: subject,
                object: EventObject(kind: "file", path: target)
            )

        case ES_EVENT_TYPE_NOTIFY_CREATE:
            let target = createTargetPath(msg.event.create)
            return event("create", target: target, object: EventObject(kind: "file", path: target))

        case ES_EVENT_TYPE_NOTIFY_WRITE:
            let target = path(for: msg.event.write.target)
            return event("write", target: target, object: EventObject(kind: "file", path: target))

        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            let close = msg.event.close
            let target = path(for: close.target)
            return event(
                "close",
                target: target,
                object: EventObject(kind: "file", path: target),
                metadata: ["modified": String(close.modified)]
            )

        case ES_EVENT_TYPE_NOTIFY_RENAME:
            let rename = msg.event.rename
            let source = path(for: rename.source) ?? ""
            let destination = renameTargetPath(rename) ?? ""
            return event(
                "rename",
                target: "\(source) -> \(destination)",
                object: EventObject(kind: "file", path: destination),
                metadata: ["source": source, "destination": destination]
            )

        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            let target = path(for: msg.event.unlink.target)
            return event("unlink", target: target, object: EventObject(kind: "file", path: target))

        case ES_EVENT_TYPE_NOTIFY_MMAP:
            let target = path(for: msg.event.mmap.source)
            return event("mmap", target: target, object: EventObject(kind: "file", path: target))

        case ES_EVENT_TYPE_NOTIFY_UIPC_BIND:
            let target = joinPath(
                dir: msg.event.uipc_bind.dir, filename: msg.event.uipc_bind.filename)
            return event(
                "uipc_bind", target: target, object: EventObject(kind: "unix_socket", path: target))

        case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
            let uipc = msg.event.uipc_connect
            let target = path(for: uipc.file)
            return event(
                "uipc_connect",
                target: target,
                object: EventObject(kind: "unix_socket", path: target),
                metadata: [
                    "domain": String(uipc.domain),
                    "type": String(uipc.type),
                    "protocol": String(uipc.protocol),
                ]
            )

        case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT:
            let service = string(from: msg.event.xpc_connect.pointee.service_name)
            return event(
                "xpc_connect", target: service,
                object: EventObject(kind: "xpc_service", name: service))

        case ES_EVENT_TYPE_NOTIFY_PROC_CHECK:
            let procCheck = msg.event.proc_check
            return event(
                "proc_check",
                target: processDescription(procCheck.target),
                object: processObject(procCheck.target, messageVersion: msg.version)
            )

        case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME:
            let procControl = msg.event.proc_suspend_resume
            return event(
                "proc_suspend_resume",
                target: processDescription(procControl.target),
                object: processObject(procControl.target, messageVersion: msg.version),
                metadata: ["type": String(procControl.type.rawValue)]
            )

        case ES_EVENT_TYPE_NOTIFY_TRACE:
            return event(
                "trace",
                target: processDescription(msg.event.trace.target),
                object: processObject(msg.event.trace.target, messageVersion: msg.version)
            )

        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
            return event(
                "remote_thread_create",
                target: processDescription(msg.event.remote_thread_create.target),
                object: processObject(
                    msg.event.remote_thread_create.target, messageVersion: msg.version)
            )

        case ES_EVENT_TYPE_NOTIFY_SIGNAL:
            let signal = msg.event.signal
            return event(
                "signal",
                target: processDescription(signal.target),
                object: processObject(signal.target, messageVersion: msg.version),
                metadata: ["signal": String(signal.sig)]
            )

        case ES_EVENT_TYPE_NOTIFY_SETUID:
            return event(
                "setuid", target: "uid=\(msg.event.setuid.uid)",
                metadata: ["uid": String(msg.event.setuid.uid)])

        case ES_EVENT_TYPE_NOTIFY_SETGID:
            return event(
                "setgid", target: "gid=\(msg.event.setgid.gid)",
                metadata: ["gid": String(msg.event.setgid.gid)])

        case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
            return event(
                "cs_invalidated", target: processPath,
                object: EventObject(
                    kind: "process", path: processPath, pid: processPID, ppid: process.ppid))

        case ES_EVENT_TYPE_NOTIFY_GET_TASK:
            let getTask = msg.event.get_task
            return event(
                "get_task",
                target: processDescription(getTask.target),
                object: processObject(getTask.target, messageVersion: msg.version),
                metadata: ["type": String(getTask.type.rawValue)]
            )

        case ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME:
            let getTask = msg.event.get_task_name
            return event(
                "get_task_name",
                target: processDescription(getTask.target),
                object: processObject(getTask.target, messageVersion: msg.version),
                metadata: ["type": String(getTask.type.rawValue)]
            )

        case ES_EVENT_TYPE_NOTIFY_GET_TASK_READ:
            let getTask = msg.event.get_task_read
            return event(
                "get_task_read",
                target: processDescription(getTask.target),
                object: processObject(getTask.target, messageVersion: msg.version),
                metadata: ["type": String(getTask.type.rawValue)]
            )

        case ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT:
            let getTask = msg.event.get_task_inspect
            return event(
                "get_task_inspect",
                target: processDescription(getTask.target),
                object: processObject(getTask.target, messageVersion: msg.version),
                metadata: ["type": String(getTask.type.rawValue)]
            )

        case ES_EVENT_TYPE_NOTIFY_KEXTLOAD:
            let identifier = string(from: msg.event.kextload.identifier)
            return event(
                "kextload", target: identifier,
                metadata: ["identifier": identifier])

        case ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD:
            let identifier = string(from: msg.event.kextunload.identifier)
            return event(
                "kextunload", target: identifier,
                metadata: ["identifier": identifier])

        case ES_EVENT_TYPE_NOTIFY_MOUNT:
            let mount = msg.event.mount
            var meta: [String: String] = [:]
            meta["mount_point"] = statfsMountPoint(mount.statfs)
            meta["device"] = statfsDevice(mount.statfs)
            if msg.version >= 8 {
                meta["disposition"] = String(mount.disposition.rawValue)
            }
            return event("mount", target: meta["mount_point"], metadata: nonEmpty(meta))

        case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
            let unmount = msg.event.unmount
            var meta: [String: String] = [:]
            meta["mount_point"] = statfsMountPoint(unmount.statfs)
            meta["device"] = statfsDevice(unmount.statfs)
            return event("unmount", target: meta["mount_point"], metadata: nonEmpty(meta))

        case ES_EVENT_TYPE_NOTIFY_REMOUNT:
            let remount = msg.event.remount
            var meta: [String: String] = [:]
            meta["mount_point"] = statfsMountPoint(remount.statfs)
            meta["device"] = statfsDevice(remount.statfs)
            if msg.version >= 8 {
                meta["remount_flags"] = String(remount.remount_flags)
                meta["disposition"] = String(remount.disposition.rawValue)
            }
            return event("remount", target: meta["mount_point"], metadata: nonEmpty(meta))

        case ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN:
            let iokit = msg.event.iokit_open
            var meta: [String: String] = [
                "user_client_type": String(iokit.user_client_type),
                "user_client_class": string(from: iokit.user_client_class),
            ]
            if msg.version >= 10 {
                meta["parent_registry_id"] = String(iokit.parent_registry_id)
                meta["parent_path"] = string(from: iokit.parent_path)
            }
            return event("iokit_open", target: meta["user_client_class"], metadata: nonEmpty(meta))

        case ES_EVENT_TYPE_NOTIFY_MPROTECT:
            let mprotect = msg.event.mprotect
            return event(
                "mprotect",
                target:
                    "addr=\(mprotect.address) size=\(mprotect.size) prot=\(mprotect.protection)",
                metadata: [
                    "address": String(mprotect.address),
                    "size": String(mprotect.size),
                    "protection": String(mprotect.protection),
                ]
            )

        case ES_EVENT_TYPE_NOTIFY_LINK:
            let link = msg.event.link
            let source = path(for: link.source) ?? ""
            let targetDir = path(for: link.target_dir) ?? ""
            let targetFilename = string(from: link.target_filename)
            let targetPath =
                targetDir.isEmpty
                ? targetFilename
                : URL(fileURLWithPath: targetDir).appendingPathComponent(targetFilename).path
            return event(
                "link",
                target: "\(source) -> \(targetPath)",
                object: EventObject(kind: "file", path: targetPath),
                metadata: ["source": source, "target": targetPath]
            )

        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
            let setextattr = msg.event.setextattr
            let target = path(for: setextattr.target)
            return event(
                "setextattr",
                target: target,
                object: EventObject(kind: "file", path: target),
                metadata: ["extattr": string(from: setextattr.extattr)]
            )

        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
            let btm = msg.event.btm_launch_item_add.pointee
            let item = btm.item.pointee
            let meta: [String: String] = [
                "executable_path": string(from: btm.executable_path),
                "item_type": btmItemTypeName(item.item_type),
                "item_url": string(from: item.item_url),
                "app_url": string(from: item.app_url),
                "legacy": String(item.legacy),
                "managed": String(item.managed),
                "uid": String(item.uid),
            ]
            return event("btm_launch_item_add", target: meta["item_url"], metadata: nonEmpty(meta))

        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE:
            let btm = msg.event.btm_launch_item_remove.pointee
            let item = btm.item.pointee
            let meta: [String: String] = [
                "item_type": btmItemTypeName(item.item_type),
                "item_url": string(from: item.item_url),
                "app_url": string(from: item.app_url),
                "legacy": String(item.legacy),
                "managed": String(item.managed),
                "uid": String(item.uid),
            ]
            return event(
                "btm_launch_item_remove", target: meta["item_url"], metadata: nonEmpty(meta))

        case ES_EVENT_TYPE_NOTIFY_SETEUID:
            return event(
                "seteuid", target: "euid=\(msg.event.seteuid.euid)",
                metadata: ["euid": String(msg.event.seteuid.euid)])

        case ES_EVENT_TYPE_NOTIFY_SETEGID:
            return event(
                "setegid", target: "egid=\(msg.event.setegid.egid)",
                metadata: ["egid": String(msg.event.setegid.egid)])

        case ES_EVENT_TYPE_NOTIFY_SETREUID:
            return event(
                "setreuid",
                target: "ruid=\(msg.event.setreuid.ruid) euid=\(msg.event.setreuid.euid)",
                metadata: [
                    "ruid": String(msg.event.setreuid.ruid),
                    "euid": String(msg.event.setreuid.euid),
                ]
            )

        case ES_EVENT_TYPE_NOTIFY_SETREGID:
            return event(
                "setregid",
                target: "rgid=\(msg.event.setregid.rgid) egid=\(msg.event.setregid.egid)",
                metadata: [
                    "rgid": String(msg.event.setregid.rgid),
                    "egid": String(msg.event.setregid.egid),
                ]
            )

        case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN:
            let login = msg.event.openssh_login.pointee
            let success = login.success ? "success" : "failure"
            let username = string(from: login.username)
            let sourceAddress = string(from: login.source_address)
            return event(
                "openssh_login",
                target: "\(success) user=\(username) source=\(sourceAddress)",
                object: EventObject(kind: "remote_login", name: username),
                metadata: [
                    "success": String(login.success), "username": username,
                    "source_address": sourceAddress,
                ]
            )

        case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT:
            let logout = msg.event.openssh_logout.pointee
            let username = string(from: logout.username)
            let sourceAddress = string(from: logout.source_address)
            return event(
                "openssh_logout",
                target: "user=\(username) source=\(sourceAddress)",
                object: EventObject(kind: "remote_login", name: username),
                metadata: ["username": username, "source_address": sourceAddress]
            )

        case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH:
            let attach = msg.event.screensharing_attach.pointee
            let success = attach.success ? "success" : "failure"
            let sourceAddress = string(from: attach.source_address)
            let username = string(from: attach.authentication_username)
            return event(
                "screensharing_attach",
                target: "\(success) source=\(sourceAddress) user=\(username)",
                object: EventObject(kind: "remote_session", name: username),
                metadata: [
                    "success": String(attach.success), "source_address": sourceAddress,
                    "username": username,
                ]
            )

        case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH:
            let detach = msg.event.screensharing_detach.pointee
            let sourceAddress = string(from: detach.source_address)
            return event(
                "screensharing_detach",
                target: "source=\(sourceAddress)",
                object: EventObject(kind: "remote_session"),
                metadata: ["source_address": sourceAddress]
            )

        default:
            return nil
        }
    }

    private static func statfsMountPoint(_ statfs: UnsafePointer<statfs>?) -> String? {
        guard let statfs = statfs else { return nil }
        return withUnsafeBytes(of: statfs.pointee.f_mntonname) { ptr in
            String(cString: ptr.bindMemory(to: CChar.self).baseAddress!)
        }
    }

    private static func statfsDevice(_ statfs: UnsafePointer<statfs>?) -> String? {
        guard let statfs = statfs else { return nil }
        return withUnsafeBytes(of: statfs.pointee.f_mntfromname) { ptr in
            String(cString: ptr.bindMemory(to: CChar.self).baseAddress!)
        }
    }

    private static func btmItemTypeName(_ type: es_btm_item_type_t) -> String {
        switch type {
        case ES_BTM_ITEM_TYPE_USER_ITEM: return "user_item"
        case ES_BTM_ITEM_TYPE_APP: return "app"
        case ES_BTM_ITEM_TYPE_LOGIN_ITEM: return "login_item"
        case ES_BTM_ITEM_TYPE_AGENT: return "agent"
        case ES_BTM_ITEM_TYPE_DAEMON: return "daemon"
        default: return "unknown(\(type.rawValue))"
        }
    }

    private static func path(for file: UnsafePointer<es_file_t>?) -> String? {
        guard let file else { return nil }
        return string(from: file.pointee.path)
    }

    private static func string(from token: es_string_token_t) -> String {
        guard token.length > 0, let data = token.data else {
            return ""
        }
        let buffer = UnsafeRawBufferPointer(start: data, count: Int(token.length))
        return String(decoding: buffer, as: UTF8.self)
    }

    private static func createTargetPath(_ create: es_event_create_t) -> String? {
        if create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
            return path(for: create.destination.existing_file)
        }
        return joinPath(
            dir: create.destination.new_path.dir, filename: create.destination.new_path.filename)
    }

    private static func renameTargetPath(_ rename: es_event_rename_t) -> String? {
        if rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
            return path(for: rename.destination.existing_file)
        }
        return joinPath(
            dir: rename.destination.new_path.dir, filename: rename.destination.new_path.filename)
    }

    private static func joinPath(dir: UnsafePointer<es_file_t>?, filename: es_string_token_t)
        -> String?
    {
        guard let directory = path(for: dir) else {
            return string(from: filename)
        }
        let name = string(from: filename)
        guard !name.isEmpty else {
            return directory
        }
        return URL(fileURLWithPath: directory).appendingPathComponent(name).path
    }

    private static func processDescription(_ process: UnsafePointer<es_process_t>?) -> String? {
        guard let process else { return nil }
        let pid = audit_token_to_pid(process.pointee.audit_token)
        let executable = path(for: process.pointee.executable) ?? ""
        return "pid=\(pid) path=\(executable)"
    }

    private static func processObject(
        _ process: UnsafePointer<es_process_t>?, messageVersion: UInt32
    ) -> EventObject? {
        guard let process else { return nil }
        let pid = audit_token_to_pid(process.pointee.audit_token)
        return EventObject(
            kind: "process",
            path: path(for: process.pointee.executable),
            pid: pid,
            pidversion: audit_token_to_pidversion(process.pointee.audit_token),
            ppid: process.pointee.ppid,
            ppidversion: parentPIDVersion(for: process.pointee, messageVersion: messageVersion)
        )
    }

    private static func parentPIDVersion(for process: es_process_t, messageVersion: UInt32)
        -> Int32?
    {
        guard messageVersion >= 4 else {
            return nil
        }
        return audit_token_to_pidversion(process.parent_audit_token)
    }

    private static func nonEmpty(_ metadata: [String: String]?) -> [String: String]? {
        guard let metadata else {
            return nil
        }
        let filtered = metadata.filter { !$0.value.isEmpty }
        guard !filtered.isEmpty else {
            return nil
        }
        return filtered
    }

    private static func newClientErrorDescription(_ result: es_new_client_result_t) -> String {
        switch result {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            return
                "EndpointSecurity client creation failed: missing com.apple.developer.endpoint-security.client entitlement"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            return
                "EndpointSecurity client creation failed: Full Disk Access / TCC permission not granted"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            return "EndpointSecurity client creation failed: must run as root"
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            return "EndpointSecurity client creation failed: too many connected ES clients"
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            return "EndpointSecurity client creation failed: invalid argument"
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
            return "EndpointSecurity client creation failed: internal ES subsystem error"
        default:
            return "EndpointSecurity client creation failed: \(result)"
        }
    }
}
