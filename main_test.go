package main

import (
	"bytes"
	"errors"
	"testing"

	"github.com/colibrisec/ojo/internal/cli"
)

func TestRun(t *testing.T) {
	if code := run(nil, &bytes.Buffer{}); code != 0 {
		t.Errorf("nil error: expected exit 0, got %d", code)
	}

	var buf bytes.Buffer
	if code := run(cli.ErrFindingsFound, &buf); code != 1 || buf.Len() != 0 {
		t.Errorf("ErrFindingsFound: expected exit 1 and nothing printed, got code=%d printed=%q", code, buf.String())
	}

	buf.Reset()
	if code := run(errors.New("boom"), &buf); code != 1 || buf.String() != "boom\n" {
		t.Errorf("real error: expected exit 1 and the error printed, got code=%d printed=%q", code, buf.String())
	}
}
