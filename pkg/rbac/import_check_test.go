package rbac

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var forbiddenImports = []string{
	"api-gateway/pkg/proxy",
	"api-gateway/pkg/middleware",
	"api-gateway/pkg/config",
	"api-gateway/pkg/log",
	"api-gateway/pkg/cache",
	"api-gateway/pkg/util",
	"api-gateway/internal",
}

func TestNoGatewayImports(t *testing.T) {
	root := "."
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)
		for _, imp := range forbiddenImports {
			if strings.Contains(content, `"`+imp) {
				t.Errorf("%s imports forbidden gateway package %q", path, imp)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
