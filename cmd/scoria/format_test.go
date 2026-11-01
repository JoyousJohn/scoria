package main

import "testing"

func TestHumanBytesAddsThousandsSeparators(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{1023, "1023 B"},
		{1024, "1.00 KiB"},
		{1019*1024*1024 + 734003, "1,019.70 MiB"},
	}
	for _, tc := range cases {
		if got := humanBytes(tc.n); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

func TestCommas(t *testing.T) {
	cases := map[uint64]string{
		0:       "0",
		999:     "999",
		1000:    "1,000",
		1234567: "1,234,567",
	}
	for n, want := range cases {
		if got := commas(n); got != want {
			t.Errorf("commas(%d) = %q, want %q", n, got, want)
		}
	}
}
