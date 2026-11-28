# AGENTS.md

Notes for agents working in this repo: an end-to-end encrypted tunnel between the devices on one Apple Account. [README.md](README.md) describes the design, the public API, and how an app adopts it.

## Layout (`Sources/DeviceTunnel`)

| File | Contents |
|------|----------|
| `RemoteAccessConfiguration.swift` | Per-build-flavor Keychain service names, access group, protocol name, Bonjour type, and relay namespace |
| `KeychainStore.swift` | `KeychainStoring`, `SystemKeychainStore` (data protection Keychain), `InMemoryKeychainStore` (tests) |
| `DeviceIdentity.swift` | The device's Ed25519 key (local Keychain item), endpoint ID, derived gate key, and `DeviceFingerprint` |
| `DeviceRegistry.swift` | `DeviceRecord`, `DeviceRevocation`, and the synchronized registry |
| `DeviceApprovals.swift` | A host's local, never-synchronized approval decisions |
| `TrustedHosts.swift` | A client's local, never-synchronized decisions about hosts |
| `AccessGate.swift` | The pre-SSH gate (`AccessGate`, its server and client handlers) and `AccessGateLimiter` |
| `ControlProtocol.swift` | `ClientHello`, `HostReply`, and the length-prefixed `FrameCodec` |
| `ByteStream.swift` | The `ByteStream` abstraction, `StreamSplice`, `withTimeout`, `RemoteAccessError` |
| `LoopbackTCP.swift` | `TunnelSocket` (keepalive TCP options), `TCPStream` (`NWConnection`), `LoopbackListener` (`NWListener` on 127.0.0.1) |
| `TunnelTransport.swift` | `TunnelTransport` / `TunnelConnection` protocols, `ConnectionPath` (direct or relay) |
| `ChannelByteStream.swift` | `ByteStream` over a SwiftNIO channel, and SSH channel-data framing |
| `SSHTunnel.swift` | `SSHKeys`, `SSHPipeline` (client and server setup, stream opening), `SSHTunnelConnection`, `AsyncInbox` |
| `HostPort.swift` | `host:port` parsing/formatting for published addresses, `Data` hex helpers |
| `LocalAddresses.swift` | A host's routable interface addresses and network-change monitor |
| `HostNames.swift` | `HostNames`: the forward-confirmed reverse DNS names a host publishes after its addresses |
| `ServiceDiscovery.swift` | `ServiceBrowser` (Bonjour browsing, matched to hosts by each advertisement's salted gate-key tag) and the host's blinded advertisement |
| `PathWatcher.swift` | `PathWatcher` (a dialed tunnel's Network framework path events), `DialDiagnosis`, `dialFailure(waitingOn:unsatisfiedReason:)` |
| `RemoteLog.swift` | The package's `os` loggers (subsystem `dev.bunch.DeviceTunnel`) |
| `RemoteNode.swift` | The device's endpoint: the direct listener and its health, address publication, discovery, the relay registration, and the dialer (direct routes, then the relay) |
| `RemoteHostService.swift` | Host side: authorization, approval prompts, stream forwarding |
| `RemoteHostLink.swift` | Client side: connection loop, handshake, loopback bridge, moving a relayed tunnel to a direct one |

The relay — its wire protocol, `RelayClient`, `RelayHost`, and the server — is the separate [rendezvous-relay](https://github.com/bunchjesse/rendezvous-relay) package. This package links its `RendezvousRelayClient` and `RendezvousRelayProtocol` products; the tests also link `RendezvousRelayServer`.

## Commands

```bash
swift build
swift test
```

## Rules

- **Stay application-agnostic.** Nothing here may know about a particular app: no app names in strings, log subsystems, or queue labels. Applications are told apart by `RemoteAccessConfiguration` only, and what flows through a tunnel is the host's local server's business.
- **The Keychain holds tunnel state only.** Use generic-password items in the data protection Keychain (`SystemKeychainStore`); never certificates, identities, or the legacy file-based keychain.
- **Approvals stay local.** `DeviceApprovals` must never write synchronized items: every device on the account can write the registry, so a synchronized approval could be granted by the device asking for it. The same goes for `TrustedHosts` on clients.
- **Trust needs consent on both ends.** A host admits only devices its user approved; a `RemoteHostLink` dials only hosts its user trusted. Every device on the account can write any record, so names are never evidence: prompts show `fingerprint`.
- **Revocations become local denials.** A revoked device can delete its revocation, so hosts and clients record a local denial as soon as they see one — a running host re-reads them every `revocationCheckInterval` — and hosts admit revoked keys to SSH only to tell them they're denied.
- **Nothing reaches SSH without passing the gate.** Every connection to a host, direct or relayed, starts with `AccessGate`; SSH reveals the host's key and costs a Keychain lookup per key offered. Fail closed: a Keychain error admits nothing.
- **Advertise nothing that identifies the device.** Bonjour carries only a random name and a salted tag, renewed on every network change.
- **The device key never leaves the device.** `DeviceIdentity` stores it as a local, device-pinned item.
- **Keep registry writes rare.** `DeviceRegistry.publish` skips writes that would change only the timestamp; every write is iCloud Keychain traffic to every device on the account.
- **Only depend on code that builds from source.** Some SDKs build every Swift package for `arm64e`, and prebuilt binaries or Go/Rust libraries without `arm64e` slices can't link. Swift and C packages are fine.
- **Trust keys, never addresses — or the relay.** Addresses in a record, Bonjour advertisements, and the relay are only ways to reach a peer; the access gate checks the host's gate key, and the SSH handshake checks both keys against the registry (`ClientAuthenticator`, `ServerAuthenticator`), so a stale or forged route fails to connect or fails a key check.
- **Direct before relay.** A relay route starts `relayHeadStart` after the direct ones, and a relayed tunnel keeps probing direct routes until one replaces it. Never let a relay win when a direct route answers.
- **Bound waits on SwiftNIO futures, and clean up what an abandoned wait produces late.** Futures ignore Swift cancellation, so bound waits with `withTimeout` or `firstSuccess` and pass their `discard` closure something that closes the late connection or stream.
- **NIOSSH quirks are handled where they bite.** `ChannelByteStream.finish()`, `ByteStreamHandler`, `AuthenticationWatcher`, and `PathWatcher` each document the NIOSSH behavior they work around; read them before changing the handler pipeline.
- **Every wire change is a compatibility break** for every app's shipped builds. Bump `DeviceRecord.currentProtocolVersion` and, when older peers can't be served, `RemoteHostService.minimumProtocolVersion`.

## Testing

Swift Testing only; every `@Test` and every declaration gets a `///` doc comment. Tests use `InMemoryKeychainStore`; two stores sharing one `InMemoryKeychainStore.SyncedStorage` behave like two devices on one Apple Account.

- `TunnelTests` (`TunnelFixture`) runs a real host and client bound to 127.0.0.1 with a TCP echo server standing in for the host's local server, so it exercises the access gate, the handshake, approvals, revocations, and the data path end to end with no external setup. Its `startLink` trusts the host first.
- `RelayTunnelTests` runs the same host and client through an in-process `RelayServer` (`InProcessRelay`): registration, relayed tunnels, direct preferred, and moving off the relay.
- `LinkTests` drives `RemoteHostLink` mostly through a `ScriptedTransport`, including hosts the user hasn't trusted, and `ChannelHandlerTests` drives handlers on an `EmbeddedChannel`.
