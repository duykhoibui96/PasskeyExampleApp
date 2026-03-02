//
//  ContentView.swift
//  Passkey
//
//  Created by Tony on 2/3/26.
//

import SwiftUI
import Combine
import AuthenticationServices

// MARK: - Simple types for demo server round-trips
// In a real app, you fetch these from your server which implements WebAuthn.
struct RegistrationOptions: Codable {
    let challenge: Data
    let relyingPartyID: String
    let userID: Data
    let userName: String
}

struct AuthenticationOptions: Codable {
    let challenge: Data
    let relyingPartyID: String
    let allowedCredentialIDs: [Data]?
}

// MARK: - ViewModel handling Passkey flows
@MainActor
final class PasskeyViewModel: NSObject, ObservableObject {
    @Published var status: String = "Ready"
    @Published var isBusy: Bool = false

    // Configure your RP ID (domain) to match your server and associated domain entitlement
    private let relyingPartyID = Bundle.main.object(forInfoDictionaryKey: "RPID") as? String ?? "example.com"

    // MARK: Register (Create Credential)
    func registerPasskey() {
        guard !isBusy else { return }
        isBusy = true
        status = "Requesting registration options…"

        // 1) Fetch options from your server (challenge, user, rpId). Here we synthesize demo values.
        let options = makeDemoRegistrationOptions()

        // 2) Create a platform provider with your RP ID
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: options.relyingPartyID)

        // 3) Create a registration request
        let request = provider.createCredentialRegistrationRequest(challenge: options.challenge, name: options.userName, userID: options.userID)

        // Optionally set display name
        // request.userName = options.userName

        // 4) Perform the authorization request
        let controller = ASAuthorizationController(authorizationRequests: [request])
        controller.delegate = self
        controller.presentationContextProvider = self
        controller.performRequests()
    }

    // MARK: Authenticate (Assertion)
    func authenticateWithPasskey() {
        guard !isBusy else { return }
        isBusy = true
        status = "Requesting authentication options…"

        // 1) Fetch assertion options from your server. Here we synthesize demo values.
        let options = makeDemoAuthenticationOptions()

        // 2) Create provider and request
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: options.relyingPartyID)
        let request = provider.createCredentialAssertionRequest(challenge: options.challenge)

        if let allowedIDs = options.allowedCredentialIDs, !allowedIDs.isEmpty {
            request.allowedCredentials = allowedIDs.map { ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0) }
        }

        // 3) Perform the authorization request
        let controller = ASAuthorizationController(authorizationRequests: [request])
        controller.delegate = self
        controller.presentationContextProvider = self
        controller.performRequests()
    }
}

// MARK: - ASAuthorizationControllerDelegate
extension PasskeyViewModel: ASAuthorizationControllerDelegate {
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        defer { isBusy = false }

        switch authorization.credential {
        case let registration as ASAuthorizationPlatformPublicKeyCredentialRegistration:
            let attestationB64 = registration.rawAttestationObject?.base64EncodedString() ?? "<nil>"
            let clientDataB64 = registration.rawClientDataJSON.base64EncodedString()
            let credentialIDB64 = registration.credentialID.base64EncodedString()
            // Normally: POST to /webauthn/register/finish with attestation, clientDataJSON, and credentialID
            status = "Registered passkey (id: \(credentialIDB64))\nattestation: \(attestationB64)\nclientData: \(clientDataB64)\nSend to server to finalize."

        case let assertion as ASAuthorizationPlatformPublicKeyCredentialAssertion:
            let authenticatorDataB64 = assertion.rawAuthenticatorData.base64EncodedString()
            let clientDataB64 = assertion.rawClientDataJSON.base64EncodedString()
            let signatureB64 = assertion.signature.base64EncodedString()
            let userIDB64 = assertion.userID?.base64EncodedString() ?? "<nil>"
            let credentialIDB64 = assertion.credentialID.base64EncodedString()
            // Normally: POST to /webauthn/authenticate/finish with these values
            status = "Authenticated with passkey (id: \(credentialIDB64))\nuserID: \(userIDB64)\nauthenticatorData: \(authenticatorDataB64)\nclientData: \(clientDataB64)\nsignature: \(signatureB64)\nSend assertion to server to verify."

        default:
            status = "Received unsupported credential type."
        }
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        isBusy = false
        status = "Authorization failed: \(error.localizedDescription)"
    }
}

// MARK: - ASAuthorizationControllerPresentationContextProviding
extension PasskeyViewModel: ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        // Provide a valid window; on iOS this is typically the key window.
        return UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap { $0.windows }
            .first { $0.isKeyWindow } ?? UIWindow()
    }
}

// MARK: - Demo option builders (replace with real server calls)
private extension PasskeyViewModel {
    func makeDemoRegistrationOptions() -> RegistrationOptions {
        let challenge = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let userID = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        return RegistrationOptions(
            challenge: challenge,
            relyingPartyID: relyingPartyID,
            userID: userID,
            userName: "tony@example.com"
        )
    }

    func makeDemoAuthenticationOptions() -> AuthenticationOptions {
        let challenge = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        // Optionally scope to a known credential id if you store it
        let allowed: [Data]? = nil
        return AuthenticationOptions(
            challenge: challenge,
            relyingPartyID: relyingPartyID,
            allowedCredentialIDs: allowed
        )
    }
}

// MARK: - UI
struct ContentView: View {
    @StateObject private var viewModel = PasskeyViewModel()

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Passkey Demo")
                        .font(.title.bold())
                    Text("Register and authenticate using platform passkeys.")
                        .foregroundStyle(.secondary)
                        .font(.subheadline)
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                VStack(spacing: 12) {
                    Button {
                        viewModel.registerPasskey()
                    } label: {
                        Label("Register Passkey", systemImage: "key.fill")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(viewModel.isBusy)

                    Button {
                        viewModel.authenticateWithPasskey()
                    } label: {
                        Label("Sign In with Passkey", systemImage: "person.badge.key.fill")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .disabled(viewModel.isBusy)
                }

                GroupBox("Status") {
                    ScrollView {
                        Text(viewModel.status)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .monospaced()
                    }
                    .frame(maxHeight: 180)
                }

                if viewModel.isBusy {
                    ProgressView("Working…")
                }

                Spacer()

                VStack(spacing: 6) {
                    Text("Note: Replace demo option builders with real server calls implementing WebAuthn.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Text("Ensure Associated Domains and entitlement for your RP ID (applinks and webcredentials).")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .padding()
            .navigationTitle("Passkeys")
        }
    }
}

#Preview {
    ContentView()
}
