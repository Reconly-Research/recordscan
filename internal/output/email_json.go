package output

import (
	"encoding/json"
	"os"
	"path/filepath"

	"recordscan/internal/model"
)

// WriteEmailSecJSON writes email-sec-scan.json (full email assessment).
func WriteEmailSecJSON(baseDir string, rep model.EmailSecReport) (Paths, error) {
	path := filepath.Join(baseDir, "email-sec-scan.json")
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return Paths{}, err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return Paths{}, err
	}
	return Paths{ScanJSON: path}, nil
}
