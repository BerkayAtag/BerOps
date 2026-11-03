//go:build !windows

package paths

import "os"

// Secure, veri dizinini yalnızca root'un erişebileceği hâle getirir.
func Secure(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}
