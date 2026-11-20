// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

package sysproxy

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"
)

const commandTimeout = 10 * time.Second

// Runner runs the desktop's own configuration tools (gsettings, kwriteconfig, networksetup). It never
// goes through a shell: every argument is passed separately.
type Runner interface {
	// Look reports whether an executable is on PATH.
	Look(name string) bool
	// Run returns the combined output and the exit code. The error is only for a command that could not
	// run at all or did not finish in time; a non-zero exit is not an error.
	Run(name string, args ...string) (output string, exitCode int, err error)
}

type execRunner struct{}

func (execRunner) Look(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (execRunner) Run(name string, args ...string) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if ctx.Err() != nil {
		return out.String(), -1, errors.New(name + " did not finish in time")
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return out.String(), exit.ExitCode(), nil
	}
	if err != nil {
		return out.String(), -1, err
	}
	return out.String(), 0, nil
}
