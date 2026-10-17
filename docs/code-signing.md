# Code signing

Releases are built by GitHub Actions from the tagged source (`.github/workflows/release.yml`). Signing switches on by
itself once the secrets below exist; without them macOS builds are signed ad hoc and Windows builds are unsigned, so
releases never break.

## Code signing policy

- **Windows:** free code signing provided by [SignPath.io](https://about.signpath.io), certificate by
  [SignPath Foundation](https://signpath.org).
- **macOS:** signed with PoliNetwork APS's Developer ID (team `842636PS9J`) and notarized by Apple.
- **What is signed:** only binaries built by this repository's Release workflow from a tagged commit of `main`.
- **Who approves:** PoliNetwork APS maintainers with write access to this repository review and merge every change;
  a release is a tag pushed by a maintainer.
- **Privacy:** the agent sends nothing to PoliNetwork or third parties except the signing request the user starts
  from the PoliNetwork dashboard: the signer's certificate and the signature of one document digest. The PIN never
  leaves the computer.

## macOS: Developer ID and notarization

Done once, by someone with the Account Holder or Admin role on the PoliNetwork APS Apple Developer account.

1. On the Mac that holds the private key, create the certificate request (already done once; the key is in
   `~/dev/polinetwork/.signing/sign-agent/`, never commit it):

   ```sh
   ./scripts/setup-macos-signing.sh csr
   ```

2. At <https://developer.apple.com/account/resources/certificates/add> choose **Developer ID Application**
   (profile type G2 Sub-CA), upload `developer-id.csr`, download the `.cer`.
3. At <https://appstoreconnect.apple.com/access/integrations/api> create a **Team key** with the **Developer** role,
   download `AuthKey_<KEY ID>.p8` (only downloadable once) and note the **Key ID** and the **Issuer ID** above the list.
4. Store the GitHub secrets (needs `gh` with admin rights on the repository):

   ```sh
   ./scripts/setup-macos-signing.sh secrets ~/Downloads/developerID_application.cer \
     ~/Downloads/AuthKey_<KEY ID>.p8 <KEY ID> <ISSUER ID>
   ```

5. Push a new tag (`git tag -a v0.1.2 -m … && git push origin v0.1.2`). The macOS job signs with the hardened runtime and
   the `com.apple.security.cs.disable-library-validation` entitlement (the agent loads the CIE middleware, signed by
   IPZS), notarizes the `.zip` and the `.dmg` and staples the tickets.

Secrets used: `MACOS_CERTIFICATE_P12`, `MACOS_CERTIFICATE_PASSWORD`, `APPLE_API_KEY_P8`, `APPLE_API_KEY_ID`,
`APPLE_API_ISSUER_ID`. The Developer ID certificate lasts five years; renew it with the same steps.

## Windows: SignPath Foundation

SignPath Foundation signs open-source projects for free; the certificate names "SignPath Foundation" as publisher.

1. Apply at <https://signpath.org/apply> for `PoliNetworkOrg/sign-agent` (MIT, public, automated builds, released
   since v0.1.0). Point them to this policy.
2. Once approved, in SignPath create (or receive) a project with a GitHub trusted build system, an artifact
   configuration that signs `sign-agent.exe` inside the Windows `.zip`, and a release signing policy.
3. Set the repository variables and secret:

   ```sh
   gh variable set SIGNPATH_ORGANIZATION_ID --repo PoliNetworkOrg/sign-agent --body <organization id>
   gh variable set SIGNPATH_PROJECT_SLUG --repo PoliNetworkOrg/sign-agent --body <project slug>
   gh variable set SIGNPATH_SIGNING_POLICY_SLUG --repo PoliNetworkOrg/sign-agent --body release-signing
   gh variable set SIGNPATH_ARTIFACT_CONFIGURATION_SLUG --repo PoliNetworkOrg/sign-agent --body <configuration slug>
   gh secret set SIGNPATH_API_TOKEN --repo PoliNetworkOrg/sign-agent   # a CI user's API token
   ```

The next tagged release submits the Windows build to SignPath and publishes the signed zip.

**Alternative with PoliNetwork as publisher:** Azure Artifact Signing (formerly Trusted Signing), about $9.99 a month,
needs a paid (not sponsored or credit-only) Azure subscription and verification of PoliNetwork APS as an organization.
It would replace the SignPath step with `azure/trusted-signing-action`.
