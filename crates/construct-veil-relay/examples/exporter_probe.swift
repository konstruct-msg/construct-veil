// The Apple half of the exporter probe. See exporter_probe.rs for what is being decided.
//
// Connects to the Rust server with Network.framework — the same stack an iOS app would use if we
// stopped shipping rustls on the client — and asks Security.framework for the TLS exporter of the
// very same session the server just derived one for.
//
// Certificate verification is switched off on purpose: the server is a throwaway self-signed cert
// and the question is about the exporter, not about trust. Nothing here is shipped.
//
// Run: swift exporter_probe.swift <port>

import Foundation
import Network
import Security

let label = "construct veil-front auth v1"   // EXPORTER_LABEL
let exporterLength = 32                      // EXPORTER_LEN

guard let port = UInt16(CommandLine.arguments.dropFirst().first ?? ""),
      let nwPort = NWEndpoint.Port(rawValue: port) else {
    print("usage: swift exporter_probe.swift <port>")
    exit(2)
}

let tls = NWProtocolTLS.Options()
sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv13)
sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, "h2")
// Throwaway self-signed server: accept it and get on with the actual question.
sec_protocol_options_set_verify_block(
    tls.securityProtocolOptions,
    { _, _, complete in complete(true) },
    DispatchQueue.global()
)

let connection = NWConnection(
    host: .ipv4(.loopback),
    port: nwPort,
    using: NWParameters(tls: tls)
)

let done = DispatchSemaphore(value: 0)
var exitCode: Int32 = 1

connection.stateUpdateHandler = { state in
    switch state {
    case .ready:
        guard let metadata = connection.metadata(definition: NWProtocolTLS.definition)
                as? NWProtocolTLS.Metadata else {
            print("swift    : no TLS metadata")
            done.signal()
            return
        }
        let sec = metadata.securityProtocolMetadata

        let negotiated = sec_protocol_metadata_get_negotiated_tls_protocol_version(sec)
        print("protocol : \(negotiated)")
        if let alpn = sec_protocol_metadata_get_negotiated_protocol(sec) {
            print("alpn     : \(String(cString: alpn))")
        }

        // The API under test. Public since iOS 12 / macOS 10.14.
        guard let secret = label.withCString({ cLabel in
            sec_protocol_metadata_create_secret(sec, strlen(cLabel), cLabel, exporterLength)
        }) else {
            print("swift    : sec_protocol_metadata_create_secret returned nil")
            done.signal()
            return
        }

        // `dispatch_data_t` bridges to Foundation's Data, which is the readable form here.
        let bytes = [UInt8](secret as Any as! Data)
        print("label    : \"\(label)\"")
        print("swift    : \(bytes.map { String(format: "%02x", $0) }.joined())")
        exitCode = 0
        done.signal()

    case .failed(let error):
        print("swift    : connection failed — \(error)")
        done.signal()

    case .cancelled:
        done.signal()

    default:
        break
    }
}

connection.start(queue: .global())
if done.wait(timeout: .now() + 15) == .timedOut { print("swift    : timed out") }
connection.cancel()
exit(exitCode)
