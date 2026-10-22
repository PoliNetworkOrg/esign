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
	// Update says how the newest version replaces this one.
	Update string
}

// download is the newest version for goos. The macOS and Windows files have the same name in every release
// (scripts/build-macos.sh, scripts/build-windows.sh); Linux has a package per distribution, listed on the release page,
// which the package manager updates.
func download(goos string) downloadLink {
	switch goos {
	case "darwin":
		return downloadLink{
			URL:    latestRelease + "/download/PoliNetwork-eSign-macos.dmg",
			Label:  "Download for macOS",
			Update: "Download the new one, open it and open PoliNetwork eSign inside: it replaces this one.",
		}
	case "windows":
		return downloadLink{
			URL:    latestRelease + "/download/PoliNetwork-eSign-windows-amd64.zip",
			Label:  "Download for Windows",
			Update: "Download the new one, extract it and open esign.exe: it replaces this one.",
		}
	}
	return downloadLink{
		URL:    latestRelease,
		Label:  "Open the download page",
		Page:   true,
		Update: "Update the polinetwork-esign package, or install the new one from the download page.",
	}
}
