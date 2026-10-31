package cli

import "testing"

func TestFileOf(t *testing.T) {
	cases := []struct {
		file string
		ser  int
		want string
	}{
		{"a.png", 0, "a.png"},
		{"a.png", 1, "a_1.png"},
		{"test/a.png", 3, "test/a_3.png"},
		{".out", 1, ".out_1"},
		{"dir/.out", 2, "dir/.out_2"},
		{"foo.", 1, "foo_1."},
		{"dir/foo.tar.gz", 1, "dir/foo.tar_1.gz"},
	}
	for _, tc := range cases {
		if got := fileOf(tc.file, tc.ser); got != tc.want {
			t.Errorf("fileOf(%q,%d) = %q, want %q", tc.file, tc.ser, got, tc.want)
		}
	}
}
