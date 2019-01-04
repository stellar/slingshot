// +build ignore

// This runs at "go generate" time, producing opgen.go from op/op.go.

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
)

func main() {
	ops := getOps()
	opgenName := "opgen.go"
	out, err := os.Create(opgenName)
	must(err)
	fmt.Fprint(out, "// Auto-generated from op/op.go by gen.go\n\npackage txvm\n\n")
	fmt.Fprintln(out, `import "i10r.io/protocol/txvm/op"`)

	fmt.Fprint(out, "var opFuncs [256]func(*VM)\n\n")

	fmt.Fprint(out, "func init() {\n")
	for _, op := range ops {
		fmt.Fprintf(out, "\topFuncs[op.%s] = op%s\n", op, op)
	}
	fmt.Fprint(out, "}\n")

	out.Close()

	cmd := exec.Command("gofmt", "-w", opgenName)
	must(cmd.Run())
}

func getOps() []string {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "op/op.go", nil, 0)
	must(err)
	var constDecl *ast.GenDecl
	for _, d := range f.Decls {
		if gendecl, ok := d.(*ast.GenDecl); ok && gendecl.Tok == token.CONST {
			constDecl = gendecl
			break
		}
	}
	if constDecl == nil {
		panic("op/op.go has no top-level const declaration")
	}
	var ops []string
	for _, spec := range constDecl.Specs {
		vspec, ok := spec.(*ast.ValueSpec)
		if !ok {
			panic("const decl contains non-const values?!")
		}
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
