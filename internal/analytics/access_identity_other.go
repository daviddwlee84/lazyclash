//go:build !windows

package analytics

import (
	"fmt"
	"os"
	"reflect"
)

// Only stable inode/device identifiers are retained; file content never enters checkpoints.
func accessFileIdentity(_ string, info os.FileInfo) string {
	v := reflect.Indirect(reflect.ValueOf(info.Sys()))
	if v.IsValid() && v.Kind() == reflect.Struct {
		d, i := v.FieldByName("Dev"), v.FieldByName("Ino")
		if d.IsValid() && i.IsValid() {
			return fmt.Sprint(d.Interface(), ":", i.Interface())
		}
	}
	return fmt.Sprintf("%s:%d", info.Name(), info.ModTime().UnixNano())
}
