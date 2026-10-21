package server

import "runtime"

func osName() string { return runtime.GOOS + "/" + runtime.GOARCH }

// latestRelease is the release page of the newest version that is not a pre-release.
const latestRelease = "https://github.com/PoliNetworkOrg/esign/releases/latest"

// downloadLink is how the signing page offers the newest version.
type downloadLink struct {
	URL   string
	Label string
	// Page is set when URL is the release page rather than the file that installs the agent.
	Page bool
}

// download is the newest version for goos. The macOS and Windows files have the same name in every release
// (scripts/build-macos.sh, scripts/build-windows.sh); Linux has a package per distribution, listed on the release page.
func download(goos string) downloadLink {
	switch goos {
	case "darwin":
		return downloadLink{URL: latestRelease + "/download/PoliNetwork-eSign-macos.dmg", Label: "Download for macOS"}
	case "windows":
		return downloadLink{URL: latestRelease + "/download/PoliNetwork-eSign-windows-amd64.zip", Label: "Download for Windows"}
	}
	return downloadLink{URL: latestRelease, Label: "Open the download page", Page: true}
}
