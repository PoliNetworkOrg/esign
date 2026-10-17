# PoliNetwork Sign Agent

A small program that lets the [PoliNetwork admin dashboard](https://github.com/PoliNetworkOrg/admin) sign PDFs with
the Italian electronic identity card (CIE) on Windows, macOS and Linux.

The dashboard opens the agent's page (`http://127.0.0.1:47321/sign`) in a popup. You type your CIE PIN there, the agent
reads the card through an NFC reader and signs; the PIN never leaves your computer. The PDF itself is prepared and
finalized by the PoliNetwork backend (PAdES), the agent only signs a digest with the card.

> Work in progress: see the tracker in the admin repository, `docs/esign/TRACKER.md`.

## What you need

- A CIE (Carta d'Identità Elettronica 3.0) and its 8-digit PIN.
- A contactless (NFC) smart-card reader, for example a bit4id miniLector AIR NFC. Most readers work without drivers on
  Windows and macOS; on Linux they need `pcscd` (see below).
- Optionally, CIE software for your system. The agent tries, in order:
  - `cie-mw`, the official middleware: **Software CIE** (Mac App Store) on macOS, **CIE ID** on Windows and Linux,
    from [cartaidentita.interno.gov.it](https://www.cartaidentita.interno.gov.it/pa-e-imprese/documentazione-middleware-cie/).
    It works only with cards "paired" on this computer, a one-time step with the full PIN. If the card is not paired
    yet, the agent pairs it through the middleware the first time you sign.
  - `opencie`, [OpenCIE](https://github.com/M0Rf30/opencie-pkcs11): put its PKCS#11 module
    (`libopencie-pkcs11.so`, `.dylib` or `.dll`) next to the agent or in the agent's configuration folder. It also
    keeps a pairing cache, which the agent creates the same way.
  - `cie`, built into the agent: it talks to the card directly over PC/SC with the CIE's IAS protocol (secure
    channel, chip authentication, PIN, signature), with no other software and no pairing. Before sending the PIN it
    checks that the card is a genuine CIE: the card's document security object must be signed by a Document Signer
    of the Italian Country Signing CA, whose certificates (CSCA00–05 from
    [csca-ita.interno.gov.it](https://csca-ita.interno.gov.it/), SHA-256 fingerprints in
    `internal/token/cie/ias/csca/SHA256SUMS`) are built into the agent, and it must cover the chip's authentication
    key and DH parameters. It is new and has not been tested on physical cards yet.

  The PIN reaches at most one of them: once a provider has sent it to the card, a failure is reported, never retried
  elsewhere.

## Install

Download the file for your system from the [latest release](https://github.com/PoliNetworkOrg/sign-agent/releases/latest).
Installing needs no administrator rights: the agent is installed for your user only, starts when you log in, and lets
the dashboard start it with a `polinetwork-sign://open` link when it is not running.

### macOS (Apple Silicon and Intel)

1. Download `PoliNetwork-Sign-Agent-<version>-macos.dmg` (or the `.zip`) and open it.
2. Open **PoliNetwork Sign Agent**. The app is not notarized yet, so macOS refuses the first time: open
   **System Settings > Privacy & Security**, choose **Open Anyway** next to the message about PoliNetwork Sign Agent,
   and confirm.
3. The app copies itself to `~/Applications`, starts at login (it appears in **System Settings > General > Login
   Items**) and opens `http://127.0.0.1:47321/` in your browser: "The agent is running".

The official Software CIE module is built for Intel Macs only. On Apple Silicon the agent runs it in a helper process
under Rosetta: if macOS offers to install Rosetta, accept (or run `softwareupdate --install-rosetta`). The first time you
sign, macOS asks whether **PoliNetwork Sign Agent** may access data from other apps: allow it, so the agent can read the
card pairing that Software CIE keeps in its own folder.

### Windows

1. Download `PoliNetwork-Sign-Agent-<version>-windows-amd64.zip`, extract it and double-click `sign-agent.exe`.
2. The program is not code-signed yet: if SmartScreen warns, choose **More info > Run anyway**.
3. It copies itself to `%LOCALAPPDATA%\PoliNetwork\SignAgent`, starts at login, appears in **Settings > Apps >
   Installed apps**, and opens `http://127.0.0.1:47321/` in your browser.

### Linux

Debian, Ubuntu and derivatives (amd64 or arm64):

```sh
sudo apt install ./polinetwork-sign-agent_<version>_amd64.deb   # installs pcscd too
systemctl --user start polinetwork-sign-agent                    # or log out and in again
```

Other distributions, from the `.tar.gz`:

```sh
tar xzf polinetwork-sign-agent-<version>-linux-amd64.tar.gz
./polinetwork-sign-agent-<version>-linux-amd64/polinetwork-sign-agent install
```

`install` copies the agent to `~/.local/bin/polinetwork-sign-agent`, starts it with a systemd user service (or an XDG
autostart entry without systemd) and registers the `polinetwork-sign://` link handler.

Cards are read through `pcscd`, which must be installed and running:

```sh
sudo apt install pcscd          # Fedora: sudo dnf install pcsc-lite; Arch: sudo pacman -S pcsclite ccid
sudo systemctl enable --now pcscd.socket
```

The official CIE ID middleware for Linux is published for x86_64 only (`.deb`, `.rpm`, `.tar.gz`); on arm64 use OpenCIE.

## Using it

In the dashboard, open a document and choose **Sign with CIE**. A small window from the agent asks for your PIN; keep
the card on the reader until it says the document is signed. If the dashboard says the agent is not running, use its
**Start the agent** link (or open the app again).

You type the PIN once even when there is more to sign: a document where you sign in several places (each place is a
separate signature), or up to 10 documents that the dashboard sends together. The window lists them, signs them one
after the other, and shows which were signed. If the dashboard refuses one document (for example because it changed),
the others are still signed; if the card stops answering, the rest are left unsigned and you can try again.

A wrong PIN uses one of the card's three attempts; the agent never retries a PIN by itself. After three wrong PINs the
card is blocked: unblock it with the PUK in the CIE software.

## Troubleshooting

`sign-agent doctor` prints what support needs: version and architecture, installation, configuration and allowed
dashboards, whether the agent is running, each CIE provider's module path and architecture, how it is loaded, the
readers it sees and whether a card is on them. It never asks for the PIN. Run it and send the output:

| System  | Command                                                                                                    |
| ------- | ---------------------------------------------------------------------------------------------------------- |
| macOS   | `~/Applications/PoliNetwork\ Sign\ Agent.app/Contents/MacOS/sign-agent doctor`                             |
| Windows | `& "$env:LOCALAPPDATA\PoliNetwork\SignAgent\sign-agent.exe" doctor > "$HOME\Desktop\doctor.txt"` (PowerShell) |
| Linux   | `polinetwork-sign-agent doctor` (or `~/.local/bin/polinetwork-sign-agent doctor`)                           |

On Windows the agent is a windowless program: in a terminal its output can appear after the prompt, so writing it to a
file as above is easier.

Common reports:

- **module: not found** — the CIE software is not installed, or is installed somewhere unusual: set its path in the
  configuration file (`pkcs11Module` or `openCieModule`).
- **loading: impossible … x86_64 only** — an Apple Silicon Mac running a build without Intel code; install the release
  app, which contains both.
- **readers: none** — the reader is not connected, or (Linux) `pcscd` is not running.
- **card: false** — put the CIE flat on the reader and keep it still.
- "This CIE is not set up on this computer yet" when signing — the middleware does not export its pairing function:
  pair the card in Software CIE / CIE ID.
- **agent: NOT running; another program uses port 47321** — close that program, or change `port` in the configuration
  (the dashboard expects 47321).

Logs: macOS `~/Library/Logs/PoliNetwork Sign Agent.log`; Windows `%APPDATA%\PoliNetwork Sign Agent\sign-agent.log`;
Linux `journalctl --user -u polinetwork-sign-agent`.

## Configuration

Optional, in `config.json` in the configuration folder (`doctor` prints it): `~/Library/Application Support/PoliNetwork
Sign Agent` on macOS, `%APPDATA%\PoliNetwork Sign Agent` on Windows, `~/.config/PoliNetwork Sign Agent` on Linux.

```json
{
  "port": 47321,
  "allowedOrigins": ["https://admin.polinetwork.org"],
  "providers": ["cie-mw", "opencie", "cie"],
  "pkcs11Module": "/path/to/libcie-pkcs11.so",
  "openCieModule": "/path/to/libopencie-pkcs11.so",
  "worker": "auto"
}
```

`worker` says when a PKCS#11 module runs in a separate helper process: `auto` when needed (another CPU architecture,
or Software CIE's environment), `always` (a crashing middleware cannot stop the agent), or `never`.

## Commands

| Command                  | What it does                                                                 |
| ------------------------ | ---------------------------------------------------------------------------- |
| `sign-agent install`     | Install for this user, start at login, register `polinetwork-sign://` links  |
| `sign-agent uninstall`   | Undo `install` and stop the agent                                            |
| `sign-agent doctor`      | Print the diagnostic report                                                  |
| `sign-agent status`      | Print readers, cards and providers                                           |
| `sign-agent [serve]`     | Run the agent in the foreground                                              |
| `sign-agent version`     | Print the version                                                            |

Opening the macOS app or double-clicking the Windows program installs it when needed, starts the agent and shows its
page. The only link the agent acts on is `polinetwork-sign://open`, and it only starts the agent.

## Development

```sh
go test ./...
./scripts/test-softhsm.sh     # PKCS#11 tests on Linux with SoftHSM2, in Docker
go run ./cmd/sign-agent --dev --soft   # development key, PIN 12345678
```

cgo is required (PKCS#11, PC/SC). On a Mac whose Command Line Tools are older than the running macOS, point cgo at
an installed SDK, for example `SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk go test ./...`.

### CIE interop harness

No physical CIE is needed to test the CIE code: `internal/token/cie/cardsim` is a card simulator (files, DH
parameters, DAPP keys, citizen key and CIE-shaped certificate, PIN and PUK counters, secure messaging checked on
every protected command), and `cmd/cie-vcard` serves it as a virtual card to vsmartcard's `vpcd` reader driver.

```sh
./scripts/interop/run.sh
```

builds a Docker image (linux/amd64; cached after the first, slow build) with the official middleware's PKCS#11 module
compiled from source (`scripts/interop/build-official.sh`), OpenCIE's released module, vpcd built from source and
pcsc-lite, then checks, each on a fresh card:

1. the official module alone, from a small C program (`scripts/interop/p11check.c`): unpaired `C_OpenSession`
   failure, `AbilitaCIE` pairing with a wrong and then the right PIN, `C_Login` with the last four digits and
   `C_Sign(CKM_RSA_PKCS)` over a SHA-256 DigestInfo, verified with OpenSSL;
2. the agent's `cie` provider through pcsc-lite: refusal of the card with the production CSCAs (its SOD is signed
   under the simulator's test CSCA, which `cie-vcard -csca-out` writes for the test to trust), status, wrong PIN with
   the remaining attempts, signature, card pulled out mid-session;
3. the agent's `cie-mw` provider on the official module, in process and in a worker: automatic pairing (wrong PIN
   first), signatures, wrong PIN once paired;
4. the same for `opencie` on OpenCIE;
5. `sign-agent status`.

The official sources are built unmodified, without optimization like the project's Eclipse "Debug" build (an
optimizing compiler turns their undefined behaviour into crashes). The simulator verifies the terminal CV
certificate that the reference builds against an RSA modulus generated for the reference's fixed root private
exponent, since the real root modulus exists only on cards; and its document security object is signed by a test Document Signer under a test CSCA:
the official code accepts it because it checks the SOD signature but not the signer's chain, while the agent's `cie`
provider accepts it only when a test hands it that CSCA.

### How signing works

The dashboard opens `/sign?origin=<dashboard>&ticket=<t1>&ticket=<t2>…`, one single-use ticket per document (1 to 10;
repeats are dropped). The page talks only to the agent:

- `POST /api/job` `{tickets, origin}` returns `{jobs: [{ticket, job} | {ticket, error}]}`;
- `POST /api/sign` `{tickets, origin, pin}` opens one card session and, for each job in order, repeats
  `prepare` (with `protocol: 2`), card signature and `complete` until the backend answers `completed`. It returns
  `{results: [{ticket, status: completed | failed | skipped, error?}], signer}`. If the session does not open (wrong
  PIN, no card) it returns that error and reports it on every job;
- `POST /api/cancel` `{tickets, origin}` reports the jobs as cancelled.

The agent calls the dashboard's `/api/esign/agent/jobs/{ticket}[/prepare|/complete|/fail]` with each ticket. A backend
older than protocol 2 sends no steps, and its jobs are signed once.

Builds:

```sh
./scripts/build-macos.sh v1.2.3    # on a Mac: universal .app, .zip, .dmg
./scripts/build-docker.sh v1.2.3   # anywhere with Docker: Linux amd64/arm64 (.tar.gz, .deb), Windows (.zip)
```

Releases: push a `v*` tag; `.github/workflows/release.yml` builds everything, adds `SHA256SUMS.txt` and publishes the
GitHub release (a pre-release for tags such as `v1.2.3-rc.1`).

### Maintainer TODO before a public release

- **macOS notarization.** The app is only signed ad hoc, so Gatekeeper blocks it until the user allows it. Sign with a
  Developer ID Application certificate, with the hardened runtime and the
  `com.apple.security.cs.disable-library-validation` entitlement (the agent loads the CIE middleware, which another team
  signed), notarize with `xcrun notarytool submit --wait` and staple (`xcrun stapler staple`) both the app and the
  `.dmg`. A stable signature also keeps macOS from asking again, after each update, for access to Software CIE's data.
- **Windows code signing** (Authenticode) of `sign-agent.exe`, to avoid SmartScreen warnings; an icon and version
  resource would help too.
- **Test on real hardware**: Windows 10/11 x64 (and Windows on ARM, which runs the x64 build emulated), Intel and Apple
  Silicon Macs with Software CIE, and the Linux distributions to support, each with a paired card.

## Code signing

Windows: free code signing provided by [SignPath.io](https://about.signpath.io), certificate by
[SignPath Foundation](https://signpath.org). macOS: signed and notarized with PoliNetwork APS's Developer ID. See
[`docs/code-signing.md`](docs/code-signing.md) for the policy and setup.
