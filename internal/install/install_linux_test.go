package install

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mimeapps.list")
	const mime = "x-scheme-handler/polinetwork-esign"
	if err := setDefault(path, mime, "a.desktop"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "[Default Applications]\n"+mime+"=a.desktop\n" {
		t.Fatalf("new file: %q", got)
	}
	existing := "[Added Associations]\ntext/plain=gedit.desktop\n[Default Applications]\ntext/html=firefox.desktop\n" + mime + "=old.desktop\n[Removed Associations]\nx=y\n"
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := setDefault(path, mime, "b.desktop"); err != nil {
		t.Fatal(err)
	}
	want := "[Added Associations]\ntext/plain=gedit.desktop\n[Default Applications]\ntext/html=firefox.desktop\n" + mime + "=b.desktop\n[Removed Associations]\nx=y\n"
	if got, _ := os.ReadFile(path); string(got) != want {
		t.Fatalf("updated file:\n%s\nwant:\n%s", got, want)
	}
	other := "[Added Associations]\ntext/plain=gedit.desktop\n"
	if err := os.WriteFile(path, []byte(other), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := setDefault(path, mime, "c.desktop"); err != nil {
		t.Fatal(err)
	}
	want = other + "[Default Applications]\n" + mime + "=c.desktop\n"
	if got, _ := os.ReadFile(path); string(got) != want {
		t.Fatalf("appended group:\n%s", got)
	}
}
