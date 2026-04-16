package output

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Paths are written artifacts for the scan.
type Paths struct {
	ScanJSON string
	PDF      string
}

// WriteJSON writes scan.json (full machine-readable report).
func WriteJSON(baseDir string, v any) (Paths, error) {
	path := filepath.Join(baseDir, "scan.json")
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return Paths{}, err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return Paths{}, err
	}
	return Paths{ScanJSON: path}, nil
}
