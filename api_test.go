package skipicore

import (
	"bytes"
	"flag"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/public_api.golden from the current sources")

const goldenPath = "testdata/public_api.golden"

// publicDecl is one exported declaration of the root package, rendered without
// comments and bodies, plus the internal/ packages its signature refers to.
type publicDecl struct {
	text     string
	internal []string
}

// collectPublicAPI parses every non-test .go file of the root package, whatever its
// build tags, so android-only and host-only files both count. gomobile binds the
// union of what the target builds expose.
func collectPublicAPI(t *testing.T) map[string]publicDecl {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	decls := map[string]publicDecl{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		imports := map[string]string{}
		for _, imp := range file.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			local := path[strings.LastIndex(path, "/")+1:]
			if imp.Name != nil {
				local = imp.Name.Name
			}
			imports[local] = path
		}
		ast.FileExports(file) // drops unexported decls, struct fields and interface methods
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				if d.Recv != nil && !ast.IsExported(receiverTypeName(d.Recv)) {
					continue
				}
				d.Body = nil
				d.Doc = nil
				add(t, decls, fset, d, imports)
			case *ast.GenDecl:
				if d.Tok == token.IMPORT {
					continue
				}
				d.Doc = nil
				for _, spec := range d.Specs {
					single := &ast.GenDecl{Tok: d.Tok, Specs: []ast.Spec{spec}}
					switch s := spec.(type) {
					case *ast.TypeSpec:
						s.Doc, s.Comment = nil, nil
					case *ast.ValueSpec:
						s.Doc, s.Comment = nil, nil
					}
					add(t, decls, fset, single, imports)
				}
			}
		}
	}
	return decls
}

func add(t *testing.T, decls map[string]publicDecl, fset *token.FileSet, node ast.Node, imports map[string]string) {
	t.Helper()
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, node); err != nil {
		t.Fatal(err)
	}
	var internal []string
	ast.Inspect(node, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok {
				if path, ok := imports[id.Name]; ok && strings.Contains(path+"/", "/internal/") {
					internal = append(internal, path)
				}
			}
		}
		return true
	})
	text := buf.String()
	decls[text] = publicDecl{text: text, internal: internal}
}

func receiverTypeName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}
	expr := recv.List[0].Type
	for {
		switch e := expr.(type) {
		case *ast.StarExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		case *ast.Ident:
			return e.Name
		default:
			return ""
		}
	}
}

func TestPublicAPIMatchesGolden(t *testing.T) {
	decls := collectPublicAPI(t)
	texts := make([]string, 0, len(decls))
	for text := range decls {
		texts = append(texts, text)
	}
	sort.Strings(texts)
	got := strings.Join(texts, "\n\n") + "\n"

	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if string(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))) != got {
		t.Fatalf("the exported API of package skipicore changed; this is a gomobile-bound surface.\n"+
			"If the change is intentional, review it and run: go test -run TestPublicAPIMatchesGolden -update\n\n--- got ---\n%s", got)
	}
}

// gomobile only binds types defined in the bound package, so no exported signature
// of the root package may mention a type from an internal/ package.
func TestPublicAPIDoesNotExposeInternalTypes(t *testing.T) {
	for text, decl := range collectPublicAPI(t) {
		if len(decl.internal) > 0 {
			t.Errorf("exported declaration references internal package(s) %v:\n%s", decl.internal, text)
		}
	}
}
