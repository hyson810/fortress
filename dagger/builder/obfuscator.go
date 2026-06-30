package main

import (
	"crypto/rand"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Obfuscator struct {
	seed       []byte
	mutations  int
	stringXor  bool
	deadCode   bool
}

func NewObfuscator() *Obfuscator {
	seed := make([]byte, 32)
	rand.Read(seed)
	return &Obfuscator{
		seed:       seed,
		mutations:  5,
		stringXor:  true,
		deadCode:   true,
	}
}

func (o *Obfuscator) Apply(srcDir string) error {
	fmt.Printf("obfuscator: seed=%x mutations=%d\n", o.seed[:8], o.mutations)
	if o.stringXor {
		if err := o.xorStrings(srcDir); err != nil {
			return fmt.Errorf("xorStrings: %w", err)
		}
	}
	if o.deadCode {
		if err := o.insertDeadCode(srcDir); err != nil {
			return fmt.Errorf("insertDeadCode: %w", err)
		}
	}
	return nil
}

// xorStrings finds string literals in Go source files and replaces them with
// an XOR-decoded form: const encoded = []byte{...}; string(decoded(encoded)).
// The XOR key is derived from the seed to be deterministic per build.
func (o *Obfuscator) xorStrings(srcDir string) error {
	key := make([]byte, 4)
	copy(key, o.seed[:4])

	return filepath.Walk(srcDir, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil // skip tests
		}

		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err // skip files with syntax errors
		}

		changed := false
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}

			// Skip short strings (<3 chars) and empty strings
			val, err := strconv.Unquote(lit.Value)
			if err != nil || len(val) < 3 {
				return true
			}

			// Skip import paths and struct tags
			if isImportOrTag(fset, lit) {
				return true
			}

			// XOR-encode the string
			encoded := xorEncode([]byte(val), key)
			lit.Value = encodeAsXorExpr(encoded, key)
			changed = true
			return true
		})

		if changed {
			outFile, err := os.Create(path)
			if err != nil {
				return err
			}
			defer outFile.Close()
			return format.Node(outFile, fset, f)
		}
		return nil
	})
}

// insertDeadCode adds unreachable blocks and junk variables into Go functions
// to alter the compiled binary's hash and frustrate signature-based detection.
func (o *Obfuscator) insertDeadCode(srcDir string) error {
	return filepath.Walk(srcDir, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		lines := strings.Split(string(data), "\n")
		var result []string
		mutationIdx := 0

		for _, line := range lines {
			result = append(result, line)

			// Insert dead code after function bodies (after closing braces at top indent)
			trimmed := strings.TrimSpace(line)
			if trimmed == "}" && mutationIdx < o.mutations {
				// Only insert in function bodies, not package/import blocks
				if strings.Contains(line, "func ") || hasFuncBefore(lines, result) {
					result = append(result, deadCodeSnippet(mutationIdx, o.seed)...)
					mutationIdx++
				}
			}
		}

		if mutationIdx > 0 {
			out := strings.Join(result, "\n")
			if err := os.WriteFile(path, []byte(out), 0644); err != nil {
				return err
			}
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func xorEncode(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

func encodeAsXorExpr(encoded, key []byte) string {
	// Build a byte slice literal from the encoded data
	var b strings.Builder
	b.WriteString("func()string{var k=[...]byte{")
	for i, v := range key {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(fmt.Sprintf("0x%02x", v))
	}
	b.WriteString("};var d=[...]byte{")
	for i, v := range encoded {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(fmt.Sprintf("0x%02x", v))
	}
	b.WriteString("};for i:=range d{d[i]^=k[i%len(k)]};return string(d[:])}()")
	return b.String()
}

func isImportOrTag(fset *token.FileSet, lit *ast.BasicLit) bool {
	pos := fset.Position(lit.Pos())
	return strings.Contains(pos.String(), "import") ||
		strings.Contains(lit.Value, "`") // struct tag
}

func hasFuncBefore(lines []string, current []string) bool {
	count := 0
	for i := len(current) - 1; i >= 0 && count < 10; i-- {
		if strings.Contains(current[i], "func ") {
			return true
		}
		count++
	}
	return false
}

func deadCodeSnippet(idx int, seed []byte) []string {
	junk := fmt.Sprintf("0x%04x", (uint16(seed[idx%len(seed)])<<8)|uint16(seed[(idx+1)%len(seed)]))
	return []string{
		"\t// obfuscated",
		fmt.Sprintf("\t_ = %s + %d // dead code", junk, idx*7+3),
	}
}

