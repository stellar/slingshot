// +build ignore

// This runs at "go generate" time, producing opgen.go from op.go.

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"strings"
)

func main() {
	ops := getOps()
	w, err := os.Create("opgen.go")
	must(err)
	fmt.Fprint(w, "// Auto-generated from op.go by gen.go.\n\n")
	fmt.Fprintln(w, "package op")

	fmt.Fprintln(w, "var name = [...]string{")
	for _, op := range ops {
		fmt.Fprintf(w, "%s: %q,\n", op, strings.ToLower(op))
	}
	fmt.Fprintln(w, "}")

	fmt.Fprintln(w, "var code = map[string]byte{")
	for _, op := range ops {
		fmt.Fprintf(w, "%q: %s,\n", strings.ToLower(op), op)
	}
	fmt.Fprintln(w, "}")

	must(w.Close())
	must(exec.Command("gofmt", "-w", "opgen.go").Run())
}

func getOps() []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "op.go", nil, 0)
	must(err)
	var constDecl *ast.GenDecl
	for _, d := range f.Decls {
		if gendecl, ok := d.(*ast.GenDecl); ok && gendecl.Tok == token.CONST {
			constDecl = gendecl
			break
		}
	}
	if constDecl == nil {
		panic("op.go has no top-level const declaration")
	}
	var ops []string
	for _, spec := range constDecl.Specs {
		vspec := spec.(*ast.ValueSpec)
		if len(vspec.Names) != 1 {
			panic(fmt.Errorf("const spec contains %d names, want 1", len(vspec.Names)))
		}
		name := vspec.Names[0].Name
		ops = append(ops, name)
	}
	return ops
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
