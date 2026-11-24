// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "device-tunnel",
    platforms: [
        .macOS("26.0"),
        .iOS("26.0"),
        .visionOS("26.0"),
    ],
    products: [
        .library(name: "DeviceTunnel", targets: ["DeviceTunnel"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.81.0"),
        .package(url: "https://github.com/apple/swift-nio-ssh.git", .upToNextMinor(from: "0.15.0")),
        .package(url: "https://github.com/apple/swift-nio-transport-services.git", from: "1.26.0"),
        .package(url: "https://github.com/bunchjesse/rendezvous-relay.git", from: "0.1.1"),
    ],
    targets: [
        .target(
            name: "DeviceTunnel",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOSSH", package: "swift-nio-ssh"),
                .product(name: "NIOTransportServices", package: "swift-nio-transport-services"),
                .product(name: "RendezvousRelayClient", package: "rendezvous-relay"),
                .product(name: "RendezvousRelayProtocol", package: "rendezvous-relay"),
            ]
        ),
        .testTarget(
            name: "DeviceTunnelTests",
            dependencies: [
                "DeviceTunnel",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOEmbedded", package: "swift-nio"),
                .product(name: "NIOTransportServices", package: "swift-nio-transport-services"),
                .product(name: "RendezvousRelayProtocol", package: "rendezvous-relay"),
                .product(name: "RendezvousRelayServer", package: "rendezvous-relay"),
            ]
        ),
    ]
)
