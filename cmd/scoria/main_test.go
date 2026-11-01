package main

import "testing"

func TestShouldAutoInteractive(t *testing.T) {
	cases := []struct {
		name          string
		nflags        int
		nargs         int
		stdinConsole  bool
		stdoutConsole bool
		want          bool
	}{
		{"double click", 0, 0, true, true, true},
		{"flag provided", 1, 0, true, true, false},
		{"positional argument", 0, 1, true, true, false},
		{"stdin redirected", 0, 0, false, true, false},
		{"stdout redirected", 0, 0, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldAutoInteractive(tc.nflags, tc.nargs, tc.stdinConsole, tc.stdoutConsole); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
