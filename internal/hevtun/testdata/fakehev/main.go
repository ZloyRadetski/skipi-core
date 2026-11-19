// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Command fakehev stands in for the hev executable in the Windows process-mode tests. It takes
// the config path as its only argument; the first line of the config ("mode: <name>") picks what
// it does.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("cannot read config:", err)
		os.Exit(9)
	}
	cfg := string(raw)
	mode, _, _ := strings.Cut(strings.TrimPrefix(strings.SplitN(cfg, "\n", 2)[0], "mode: "), " ")
	cwd, _ := os.Getwd()
	switch mode {
	case "run":
		fmt.Println("hello from fakehev cwd=" + cwd)
		time.Sleep(time.Hour)
	case "exit":
		fmt.Println("boom cwd=" + cwd)
		fmt.Fprintln(os.Stderr, "stderr-line")
		os.Exit(3)
	case "exitlater":
		time.Sleep(600 * time.Millisecond)
		os.Exit(4)
	case "flood":
		fmt.Print(strings.Repeat("x", 10000))
		os.Exit(5)
	}
	os.Exit(8)
}
