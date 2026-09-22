package configwork

import (
	"fmt"

	"github.com/daviddwlee84/lazyclash/internal/config"
)

// InspectReceipt reads a private saved receipt without verifying, activating or
// changing its source. Callers must distinguish recorded evidence from a fresh
// source comparison; Verify intentionally persists its findings instead.
func InspectReceipt(t config.Target, id string, opts Options) (Receipt, error) {
	r, err := loadReceipt(opts, id)
	if err != nil {
		return Receipt{}, err
	}
	if r.TargetID != t.ID || r.Binding != Binding(t) {
		return Receipt{}, fmt.Errorf("saved import receipt does not match this target and source binding")
	}
	return r, nil
}

// DefinitionDigest is the same semantic fingerprint used in import receipts.
// It exposes no node credentials and ignores YAML formatting differences.
func DefinitionDigest(d Definition) string {
	if d.Node == nil {
		return ""
	}
	return semantic(d.Node)
}
