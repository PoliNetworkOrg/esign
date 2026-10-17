// Package macapp tells how macOS launched the app bundle: Launch Services starts a bundle without arguments, both
// when the user opens the app and when a browser follows a polinetwork-sign:// link, and delivers the reason as an
// Apple Event.
package macapp

// Launch is how the app was launched.
type Launch struct {
	// URL is set when the app was launched, or reopened, to handle a link.
	URL string
}
