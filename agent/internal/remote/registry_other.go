//go:build !windows

package remote

import "github.com/BerkayAtag/BerOps/shared/protocol"

// RegistryList, kayıt defteri yalnızca Windows'ta vardır.
func RegistryList(string) (*protocol.RegistryKey, error) { return nil, ErrUnsupported }

// RegistrySet, kayıt defteri yalnızca Windows'ta vardır.
func RegistrySet(string, protocol.RegistryValue) (*protocol.RegistryChange, error) {
	return nil, ErrUnsupported
}

// RegistryDelete, kayıt defteri yalnızca Windows'ta vardır.
func RegistryDelete(string, string) (*protocol.RegistryChange, error) { return nil, ErrUnsupported }
