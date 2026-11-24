import os

/// The package's loggers, all under one subsystem so an app can turn them
/// up with a single `OSLogPreferences` entry.
enum RemoteLog {
    /// The subsystem every DeviceTunnel logger uses.
    static let subsystem = "dev.bunch.DeviceTunnel"

    static let host = Logger(subsystem: subsystem, category: "remote-host")
    static let link = Logger(subsystem: subsystem, category: "remote-link")
    static let discovery = Logger(subsystem: subsystem, category: "remote-discovery")
    static let tunnel = Logger(subsystem: subsystem, category: "remote-tunnel")
}
