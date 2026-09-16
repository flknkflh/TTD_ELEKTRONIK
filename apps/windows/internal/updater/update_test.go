package updater

import "testing"

func TestRejectUnsafeManifest(t *testing.T) {
	valid := Release{Platform: "windows", Version: "0.8.0", Code: VersionCode + 1, Path: "/updates/app-8.exe", Size: 123, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"http://evil/app.exe", "/updates/../app.exe", "/updates/a.exe?x=1", "/updates/app.apk"} {
		r := valid
		r.Path = path
		if r.Validate() == nil {
			t.Errorf("accepted %s", path)
		}
	}
	r := valid
	r.Code = VersionCode
	if r.Validate() == nil {
		t.Fatal("accepted downgrade")
	}
	r = valid
	r.Size = maxSize + 1
	if r.Validate() == nil {
		t.Fatal("accepted oversized download")
	}
}
