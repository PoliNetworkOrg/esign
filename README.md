# PoliNetwork Sign Agent

A small program that lets the [PoliNetwork admin dashboard](https://github.com/PoliNetworkOrg/admin) sign PDFs with
the Italian electronic identity card (CIE) on Windows, macOS and Linux.

The dashboard opens the agent's page (`http://127.0.0.1:47321/sign`) in a popup. You type your CIE PIN there, the agent
reads the card through an NFC reader and signs; the PIN never leaves your computer. The PDF itself is prepared and
finalized by the PoliNetwork backend (PAdES), the agent only signs a digest with the card.

> Work in progress: see the tracker in the admin repository, `docs/esign/TRACKER.md`.

## Development

```sh
go test ./...
./scripts/test-softhsm.sh     # PKCS#11 tests on Linux with SoftHSM2, in Docker
go run ./cmd/sign-agent --dev --soft   # development key, PIN 12345678
```
