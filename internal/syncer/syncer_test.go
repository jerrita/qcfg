package syncer

import (
	"testing"

	"github.com/jerrita/qcfg/internal/state"
)

func TestDecide(t *testing.T) {
	base := &state.Base{Rev: 1, Sha256: "b"}
	cases := []struct {
		local  string
		base   *state.Base
		remote string
		want   Action
	}{
		{"", nil, "", Empty},
		{"l", nil, "", Push},
		{"", base, "r", Pull},
		{"x", nil, "x", OK},
		{"l", nil, "r", Conflict},
		{"b", base, "r", Pull},
		{"l", base, "b", Push},
		{"l", base, "r", Conflict},
	}
	for _, c := range cases {
		if got := Decide(c.local, c.base, c.remote); got != c.want {
			t.Errorf("Decide(%q, %v, %q) = %s, want %s", c.local, c.base, c.remote, got, c.want)
		}
	}
}
