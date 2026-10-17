# Linux packages

Every release builds, for amd64 and arm64, with [nfpm](https://nfpm.goreleaser.com) (`packaging/linux/nfpm.yaml`,
`scripts/build-linux.sh`):

| File                                                  | For                                               |
| ----------------------------------------------------- | ------------------------------------------------- |
| `polinetwork-esign_<version>_<amd64\|arm64>.deb`      | Debian, Ubuntu and derivatives                    |
| `polinetwork-esign-<version>-1.<x86_64\|aarch64>.rpm` | Fedora                                            |
| `polinetwork-esign-<version>-1-<arch>.pkg.tar.zst`    | Arch (`pacman -U`), repackaged by the AUR package |
| `polinetwork-esign-<version>-linux-<arch>.tar.gz`     | anything else, with `polinetwork-esign install`   |

All three packages install the same files (the binary in `/usr/bin`, the systemd user service, the link handler) and
run the same scripts: `postinstall.sh` enables the user service for every user, enables `pcscd.socket` (Arch leaves it
off) and restarts the agent for the users logged in; `preremove.sh` undoes it on removal only.

For releases that are not pre-releases, `.github/workflows/release.yml` also publishes:

- **APT and DNF repositories** on GitHub Pages, <https://polinetworkorg.github.io/esign> (`apt/`, `rpm/`, the
  public key and a `.repo` file), built by `scripts/linux-repository.sh` and signed with the repository key. They hold
  the latest release only. The `.deb` and `.rpm` install the repository's configuration (`nfpm-repository.yaml`), so a
  user who installed a downloaded package gets later versions from `apt upgrade` or `dnf upgrade`. The `.rpm` files
  attached to the GitHub release are signed with the same key.
- **The AUR package** (not published yet: AUR registrations are closed, so Arch users install the release's Arch
  package with `pacman -U` for now) [`polinetwork-esign-bin`](https://aur.archlinux.org/packages/polinetwork-esign-bin),
  from `packaging/aur/PKGBUILD`: `scripts/aur-package.sh` fills in the version and checksums, takes the install script
  from the release's Arch package, writes `.SRCINFO`, builds it once as a check, and the workflow pushes it.

Each step is skipped with a warning while its secret is missing, so releases never break.

## Setup

Done once, by a maintainer with admin rights on the repository and `gh` signed in.

### APT and DNF repositories

```sh
./scripts/setup-linux-publishing.sh repository
git add packaging/linux/repository-key.asc && git commit -m "build: add the Linux repository key"
```

This creates an RSA 4096 signing key that does not expire, in `~/dev/polinetwork/.signing/esign/` (back it up,
never commit it), writes its public half to `packaging/linux/repository-key.asc`, stores the private key in the
`LINUX_REPOSITORY_GPG_KEY` secret, turns on GitHub Pages with GitHub Actions as its source and lets `v*` tags deploy
to the `github-pages` environment. The next release publishes the repositories, and its packages are the first to
carry the repository configuration: users of earlier versions install the new package once by hand.

Replacing the key later breaks updates for everyone until they import the new one, so keep it safe. Moving the
repositories to another address (a custom domain for Pages, for example) means changing the URLs in
`packaging/linux/repository/` and `scripts/linux-repository.sh`, and keeping the old address working until users
have updated.

### AUR

1. Create an account at <https://aur.archlinux.org/register> for PoliNetwork (for example with
   `it@polinetwork.org`).
2. Run

   ```sh
   ./scripts/setup-linux-publishing.sh aur
   ```

   which creates an SSH key, stores it in the `AUR_SSH_PRIVATE_KEY` secret and prints the public key: paste it in the
   account's **SSH Public Key** field.
3. The next release creates the package on the AUR (pushing to a new package name creates it) and updates it from then
   on. Rerunning the job for the same release changes nothing.

AUR users can flag the package out of date or comment on it; the account's email receives those notifications.

## Testing locally

```sh
./scripts/build-docker.sh v1.2.3                     # builds the packages in dist/
docker run --rm -v "$PWD/dist:/dist" fedora dnf install -y /dist/polinetwork-esign-1.2.3-1.x86_64.rpm
docker run --rm -v "$PWD/dist:/dist" debian:12 sh -c 'apt-get update && apt-get install -y /dist/polinetwork-esign_1.2.3_amd64.deb'
```

Packages built with `packaging/linux/repository-key.asc` present contain the repository configuration. Pacman inside an
emulated (non-native) container may need `DisableSandbox` in `/etc/pacman.conf`.
