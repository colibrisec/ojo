package secret

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/colibrisec/ojo/internal/fpcorpus"
)

// False-positive regression corpus: triaged false positives (source says
// where) next to must-fire twins. want is one of fpcorpus.Check's values.
var secretFPCorpus = []struct {
	name, source, file, content, rule, want string
}{
	{
		name:    "local-dev connection string in docs",
		source:  "triaged false positive",
		file:    "README.md",
		rule:    "db-connection-string",
		want:    "known",
		content: "export APP_DATABASE_URL=postgres://app:app@localhost:5432/app?sslmode=disable\n",
	},
	{
		name:    "docker-compose dev credentials",
		source:  "triaged false positive",
		file:    "docker-compose.yml",
		rule:    "db-connection-string",
		want:    "known",
		content: "services:\n  api:\n    environment:\n      APP_DATABASE_URL: postgres://app:app@db:5432/app?sslmode=disable\n",
	},
	{
		name:    "CI throwaway service password",
		source:  "triaged false positive",
		file:    "test.yml",
		rule:    "db-connection-string",
		want:    "known",
		content: "env:\n  DATABASE_URL: postgresql://postgres:test@localhost:5432/test\n",
	},
	{
		name:    "real-looking production password",
		source:  "twin",
		file:    "config.env",
		rule:    "db-connection-string",
		want:    "fire",
		content: "DATABASE_URL=postgres://app:Xq9v2LmT7pZr@prod-db.internal:5432/app\n",
	},
}

func TestSecretFalsePositiveCorpus(t *testing.T) {
	for _, c := range secretFPCorpus {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, c.file), []byte(c.content), 0o644); err != nil {
				t.Fatal(err)
			}
			issues, err := Scan(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			fpcorpus.Check(t, c.rule, c.want, c.source, issues)
		})
	}
}
