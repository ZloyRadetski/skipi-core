// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Command xrayoverlay prepares the patched xray-core SKIPI Core is built with and prints the path
// of a go.mod variant (go build -modfile) that points the xray-core module at it.
//
// xray-core is not forked or committed: patches/xray-geodata holds new files (_add/) and unified
// diffs of existing ones (modify/). This tool copies the pristine module of the version pinned in
// go.mod to build/xray-overlay/xray-core, adds the new files and applies the diffs strictly (every
// context and removed line must match, only the line offset may move), so a new xray-core that
// changes a patched place fails the build instead of being patched wrongly. go.mod and go.sum stay
// untouched. See patches/xray-geodata/README.md.
//
//	GOFLAGS="-modfile=$(go run ./tools/xrayoverlay)" go build ./...
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const xrayModule = "github.com/xtls/xray-core"

func main() {
	patchesDir := flag.String("patches", filepath.Join("patches", "xray-geodata"), "directory with _add/ and modify/")
	outDir := flag.String("out", filepath.Join("build", "xray-overlay"), "directory for the patched xray-core and the go.mod that uses it")
	flag.Parse()
	path, err := run(*patchesDir, *outDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xrayoverlay:", err)
		os.Exit(1)
	}
	fmt.Println(path)
}

func run(patchesDir, outDir string) (string, error) {
	version, moduleDir, err := xrayModuleInfo()
	if err != nil {
		return "", err
	}
	adds, err := listFiles(filepath.Join(patchesDir, "_add"), "")
	if err != nil {
		return "", err
	}
	mods, err := listFiles(filepath.Join(patchesDir, "modify"), ".patch")
	if err != nil {
		return "", err
	}
	if len(adds)+len(mods) == 0 {
		return "", fmt.Errorf("no patches found in %s", patchesDir)
	}

	outDir, err = filepath.Abs(outDir)
	if err != nil {
		return "", err
	}
	modfilePath := filepath.Join(outDir, "go.mod")
	stamp, err := stampOf(version, moduleDir, patchesDir, adds, mods)
	if err != nil {
		return "", err
	}
	stampPath := filepath.Join(outDir, "stamp")
	if got, err := os.ReadFile(stampPath); err == nil && string(got) == stamp {
		if _, err := os.Stat(modfilePath); err == nil {
			return modfilePath, nil
		}
	}

	patchedDir := filepath.Join(outDir, "xray-core")
	if err := os.RemoveAll(outDir); err != nil {
		return "", err
	}
	if err := copyTree(moduleDir, patchedDir); err != nil {
		return "", err
	}
	for _, rel := range adds {
		data, err := os.ReadFile(filepath.Join(patchesDir, "_add", rel))
		if err != nil {
			return "", err
		}
		if err := writeFile(filepath.Join(patchedDir, rel), data); err != nil {
			return "", err
		}
	}
	for _, rel := range mods {
		target := filepath.Join(patchedDir, strings.TrimSuffix(rel, ".patch"))
		orig, err := os.ReadFile(target)
		if err != nil {
			return "", fmt.Errorf("%s: patched file is missing from xray-core %s: %w", rel, version, err)
		}
		diff, err := os.ReadFile(filepath.Join(patchesDir, "modify", rel))
		if err != nil {
			return "", err
		}
		patched, err := applyUnified(string(orig), string(diff))
		if err != nil {
			return "", fmt.Errorf("%s does not apply to xray-core %s: %w\n"+
				"The patched place changed upstream: redo the patch against the new file (patches/xray-geodata/README.md)",
				rel, version, err)
		}
		if err := writeFile(target, []byte(patched)); err != nil {
			return "", err
		}
	}

	// go.mod of the main module plus a replace; go.sum next to it (go build -modfile reads <name>.sum).
	gomod, err := os.ReadFile("go.mod")
	if err != nil {
		return "", err
	}
	gosum, err := os.ReadFile("go.sum")
	if err != nil {
		return "", err
	}
	replace := fmt.Sprintf("\nreplace %s => %s\n", xrayModule, strconv.Quote(filepath.ToSlash(patchedDir)))
	if err := os.WriteFile(modfilePath, append(gomod, replace...), 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(outDir, "go.sum"), gosum, 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(stampPath, []byte(stamp), 0o644); err != nil {
		return "", err
	}
	return modfilePath, nil
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), data, 0o644)
	})
}

func xrayModuleInfo() (version, dir string, err error) {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Version}}\n{{.Dir}}", xrayModule)
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod") // the real go.mod, not the -modfile of an earlier run
	out, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("go list -m %s: %w", xrayModule, err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 || strings.TrimSpace(lines[1]) == "" {
		return "", "", fmt.Errorf("unexpected go list output %q (run go mod download)", out)
	}
	return strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1]), nil
}

// listFiles returns the slash-free relative paths of the files under dir with the given suffix.
func listFiles(dir, suffix string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, suffix) {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		out = append(out, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// stampOf identifies the inputs of an overlay: the xray version, the patches and the pristine files
// they touch, so an edited patch or a bumped xray-core regenerates it.
func stampOf(version, moduleDir, patchesDir string, adds, mods []string) (string, error) {
	h := sha256.New()
	fmt.Fprintln(h, "xrayoverlay v1", version, moduleDir)
	for _, rel := range adds {
		data, err := os.ReadFile(filepath.Join(patchesDir, "_add", rel))
		if err != nil {
			return "", err
		}
		fmt.Fprintln(h, "add", filepath.ToSlash(rel), len(data))
		h.Write(data)
	}
	for _, rel := range mods {
		data, err := os.ReadFile(filepath.Join(patchesDir, "modify", rel))
		if err != nil {
			return "", err
		}
		fmt.Fprintln(h, "modify", filepath.ToSlash(rel), len(data))
		h.Write(data)
		orig, err := os.ReadFile(filepath.Join(moduleDir, strings.TrimSuffix(rel, ".patch")))
		if err != nil {
			return "", err
		}
		h.Write(orig)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

type hunk struct {
	oldStart int // 1-based line in the old file the hunk claims to start at
	lines    []string
}

// applyUnified applies a single-file unified diff to orig. It does not use fuzz: all context and
// removed lines must match exactly, only their position may differ from the hunk header.
func applyUnified(orig, diff string) (string, error) {
	hunks, err := parseHunks(diff)
	if err != nil {
		return "", err
	}
	text := strings.ReplaceAll(orig, "\r\n", "\n")
	trailingNewline := strings.HasSuffix(text, "\n")
	src := strings.Split(strings.TrimSuffix(text, "\n"), "\n")

	var out []string
	pos := 0 // next unconsumed line of src
	for i, h := range hunks {
		var old []string
		for _, l := range h.lines {
			if l[0] == ' ' || l[0] == '-' {
				old = append(old, l[1:])
			}
		}
		at, ok := findHunk(src, old, pos, h.oldStart-1)
		if !ok {
			return "", fmt.Errorf("hunk %d (old line %d) does not match", i+1, h.oldStart)
		}
		out = append(out, src[pos:at]...)
		for _, l := range h.lines {
			if l[0] == ' ' || l[0] == '+' {
				out = append(out, l[1:])
			}
		}
		pos = at + len(old)
	}
	out = append(out, src[pos:]...)
	res := strings.Join(out, "\n")
	if trailingNewline {
		res += "\n"
	}
	return res, nil
}

// findHunk looks for old in src at or after min, starting at want and moving outwards.
func findHunk(src, old []string, min, want int) (int, bool) {
	matches := func(at int) bool {
		if at < min || at+len(old) > len(src) {
			return false
		}
		for i, l := range old {
			if src[at+i] != l {
				return false
			}
		}
		return true
	}
	if want < min {
		want = min
	}
	for d := 0; d <= len(src); d++ {
		if matches(want + d) {
			return want + d, true
		}
		if d > 0 && matches(want-d) {
			return want - d, true
		}
	}
	return 0, false
}

func parseHunks(diff string) ([]hunk, error) {
	var hunks []hunk
	var cur *hunk
	lines := strings.Split(strings.ReplaceAll(diff, "\r\n", "\n"), "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1] // the newline that ends the diff
	}
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "@@"):
			fields := strings.Fields(line) // @@ -a,b +c,d @@
			if len(fields) < 3 || !strings.HasPrefix(fields[1], "-") {
				return nil, fmt.Errorf("bad hunk header %q", line)
			}
			start, _, _ := strings.Cut(strings.TrimPrefix(fields[1], "-"), ",")
			n, err := strconv.Atoi(start)
			if err != nil {
				return nil, fmt.Errorf("bad hunk header %q", line)
			}
			hunks = append(hunks, hunk{oldStart: n})
			cur = &hunks[len(hunks)-1]
		case cur == nil, strings.HasPrefix(line, "\\"):
			// file header lines, "\ No newline at end of file"
		case line == "":
			cur.lines = append(cur.lines, " ") // a context line that lost its leading space
		case line[0] == ' ' || line[0] == '+' || line[0] == '-':
			cur.lines = append(cur.lines, line)
		default:
			return nil, fmt.Errorf("unexpected line in diff: %q", line)
		}
	}
	if len(hunks) == 0 {
		return nil, errors.New("no hunks in diff")
	}
	return hunks, nil
}
