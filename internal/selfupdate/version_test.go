package selfupdate

import "testing"

func TestStableVersions(t *testing.T) {
	for _, version := range []string{"v0.0.0", "v0.1.2", "v10.20.30", "v184467440737095516160.0.0"} {
		if !StableVersion(version) {
			t.Errorf("stable version rejected: %q", version)
		}
	}
	for _, version := range []string{"", "dev", "(devel)", "1.2.3", "v1", "v1.2", "v1.2.3.4", "v01.2.3", "v1.02.3", "v1.2.03", "v1.2.-1", "v1.2.3-beta.1", "v1.2.3+dirty", "v0.0.0-20260920120000-abcdef123456", " v1.2.3", "v1.2.3\n", "v١.2.3"} {
		if StableVersion(version) {
			t.Errorf("noncanonical stable version accepted: %q", version)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	for _, test := range []struct {
		a, b string
		want int
	}{
		{"v0.1.2", "v0.1.2", 0},
		{"v0.1.2", "v0.1.3", -1},
		{"v0.10.0", "v0.9.99", 1},
		{"v10.0.0", "v9.99.99", 1},
		{"v1.0.0", "v2.0.0", -1},
		{"v184467440737095516160.0.0", "v184467440737095516159.999.999", 1},
	} {
		got, err := CompareVersions(test.a, test.b)
		if err != nil || got != test.want {
			t.Errorf("CompareVersions(%q, %q) = %d, %v; want %d", test.a, test.b, got, err, test.want)
		}
	}
	for _, pair := range [][2]string{{"dev", "v1.0.0"}, {"v1.0.0", "v1.1.0-alpha.1"}} {
		if _, err := CompareVersions(pair[0], pair[1]); err == nil {
			t.Errorf("invalid version comparison accepted: %v", pair)
		}
	}
}
