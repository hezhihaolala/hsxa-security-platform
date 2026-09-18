package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"strings"
	"testing"
)

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{"--help"}, &stdout, &stderr)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("run(--help) error = %v; want flag.ErrHelp", err)
	}
	if !strings.Contains(stdout.String(), "-cidr") {
		t.Errorf("help output missing --cidr:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("help wrote stderr: %q", stderr.String())
	}
}

func TestRunInvalidFlagDoesNotWriteDuplicateError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{"--unknown"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected invalid flag error")
	}
	if strings.Count(stdout.String(), "Usage:") != 1 || stderr.Len() != 0 {
		t.Errorf("parse error should render usage once and return error to main; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
