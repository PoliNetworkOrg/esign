#!/usr/bin/env bash
# Sets up the Linux package channels the Release workflow publishes to. Needs `gh` signed in with admin rights on the
# repository; keys stay in $SIGNING_DIR (default ~/dev/polinetwork/.signing/esign, outside any repository).
#
#   ./scripts/setup-linux-publishing.sh repository
#       Creates the GPG key that signs the APT and DNF repositories, writes its public half to
#       packaging/linux/repository-key.asc (commit it), stores the LINUX_REPOSITORY_GPG_KEY secret and turns on GitHub
#       Pages, built by GitHub Actions and deployable from v* tags, which serves the repositories.
#
#   ./scripts/setup-linux-publishing.sh aur
#       Creates the SSH key that pushes polinetwork-esign-bin to the AUR, stores the AUR_SSH_PRIVATE_KEY secret
#       and prints the public key to add to the PoliNetwork AUR account.
#
# See docs/linux-packages.md.
set -euo pipefail
cd "$(dirname "$0")/.."
dir="${SIGNING_DIR:-$HOME/dev/polinetwork/.signing/esign}"
repo="${REPO:-PoliNetworkOrg/esign}"
mkdir -p "$dir"
chmod 700 "$dir"

case "${1:-}" in
repository)
	home="$dir/linux-repository-gnupg"
	if [ ! -d "$home" ]; then
		mkdir -p "$home" && chmod 700 "$home"
		gpg --homedir "$home" --batch --passphrase '' \
			--quick-gen-key "PoliNetwork eSign packages <admin@polinetwork.org>" rsa4096 sign never
	fi
	gpg --homedir "$home" --armor --export > packaging/linux/repository-key.asc
	gpg --homedir "$home" --armor --export-secret-keys | gh secret set LINUX_REPOSITORY_GPG_KEY --repo "$repo"
	gh api -X POST "repos/$repo/pages" -f build_type=workflow >/dev/null 2>&1 ||
		gh api -X PUT "repos/$repo/pages" -f build_type=workflow >/dev/null
	# Pages deploys only from the default branch unless allowed otherwise; releases deploy from v* tags.
	gh api -X PUT "repos/$repo/environments/github-pages" -F 'deployment_branch_policy[protected_branches]=false' \
		-F 'deployment_branch_policy[custom_branch_policies]=true' >/dev/null
	gh api -X POST "repos/$repo/environments/github-pages/deployment-branch-policies" -f name='v*' -f type=tag \
		>/dev/null 2>&1 || true
	gpg --homedir "$home" --fingerprint
	echo "Commit packaging/linux/repository-key.asc; the next release publishes the repositories."
	;;
aur)
	key="$dir/aur"
	[ -f "$key" ] || ssh-keygen -q -t ed25519 -N '' -C "esign release workflow" -f "$key"
	gh secret set AUR_SSH_PRIVATE_KEY --repo "$repo" < "$key"
	echo "Add this public key at https://aur.archlinux.org/account/ (My Account > SSH Public Key):"
	cat "$key.pub"
	;;
*)
	sed -n '2,15p' "$0"
	exit 1
	;;
esac
