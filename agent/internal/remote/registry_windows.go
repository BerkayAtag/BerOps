//go:build windows

package remote

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/BerkayAtag/BerOps/shared/protocol"
)

// maxEntries, bir anahtarda döndürülen en fazla alt anahtar ve değer sayısıdır.
const maxEntries = 2000

var hives = map[string]registry.Key{
	"HKLM": registry.LOCAL_MACHINE, "HKEY_LOCAL_MACHINE": registry.LOCAL_MACHINE,
	"HKU": registry.USERS, "HKEY_USERS": registry.USERS,
	"HKCR": registry.CLASSES_ROOT, "HKEY_CLASSES_ROOT": registry.CLASSES_ROOT,
	"HKCC": registry.CURRENT_CONFIG, "HKEY_CURRENT_CONFIG": registry.CURRENT_CONFIG,
}

// splitPath, "HKLM\SOFTWARE\Örnek" yolunu kök ve alt yol olarak ayırır.
func splitPath(p string) (registry.Key, string, error) {
	p = strings.Trim(strings.ReplaceAll(p, "/", `\`), `\ `)
	root, rest, _ := strings.Cut(p, `\`)
	k, ok := hives[strings.ToUpper(root)]
	if !ok {
		return 0, "", fmt.Errorf("geçersiz kök: %q (HKLM, HKU, HKCR, HKCC)", root)
	}
	return k, rest, nil
}

func openKey(path string, access uint32) (registry.Key, error) {
	root, sub, err := splitPath(path)
	if err != nil {
		return 0, err
	}
	if sub == "" {
		return root, nil
	}
	return registry.OpenKey(root, sub, access|registry.WOW64_64KEY)
}

var typeNames = map[uint32]string{
	registry.SZ: "REG_SZ", registry.EXPAND_SZ: "REG_EXPAND_SZ", registry.MULTI_SZ: "REG_MULTI_SZ",
	registry.DWORD: "REG_DWORD", registry.QWORD: "REG_QWORD", registry.BINARY: "REG_BINARY",
}

func readValue(k registry.Key, name string) (*protocol.RegistryValue, error) {
	_, typ, err := k.GetValue(name, nil)
	if err != nil {
		return nil, err
	}
	v := &protocol.RegistryValue{Name: name, Type: typeNames[typ]}
	switch typ {
	case registry.SZ, registry.EXPAND_SZ:
		v.Data, _, err = k.GetStringValue(name)
	case registry.MULTI_SZ:
		var ss []string
		ss, _, err = k.GetStringsValue(name)
		v.Data = strings.Join(ss, "\n")
	case registry.DWORD, registry.QWORD:
		var n uint64
		n, _, err = k.GetIntegerValue(name)
		v.Data = strconv.FormatUint(n, 10)
	default:
		var b []byte
		b, _, err = k.GetBinaryValue(name)
		v.Data = hex.EncodeToString(b)
		if v.Type == "" {
			v.Type = fmt.Sprintf("REG_TYPE_%d", typ)
		}
	}
	return v, err
}

// RegistryList, anahtarın alt anahtarlarını ve değerlerini döner.
func RegistryList(path string) (*protocol.RegistryKey, error) {
	k, err := openKey(path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("anahtar açılamadı: %w", err)
	}
	defer k.Close()
	out := &protocol.RegistryKey{Path: path, Subkeys: []string{}, Values: []protocol.RegistryValue{}}
	subs, err := k.ReadSubKeyNames(maxEntries + 1)
	// Daha az kayıt varsa io.EOF döner; bu hata değildir.
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(subs) > maxEntries {
		subs, out.Truncated = subs[:maxEntries], true
	}
	slices.SortFunc(subs, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
	out.Subkeys = subs
	names, _ := k.ReadValueNames(maxEntries + 1)
	if len(names) > maxEntries {
		names, out.Truncated = names[:maxEntries], true
	}
	slices.SortFunc(names, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
	for _, n := range names {
		if v, err := readValue(k, n); err == nil {
			out.Values = append(out.Values, *v)
		}
	}
	return out, nil
}

// RegistrySet, değeri yazar (anahtar yoksa oluşturur) ve önceki değeri döner.
func RegistrySet(path string, v protocol.RegistryValue) (*protocol.RegistryChange, error) {
	root, sub, err := splitPath(path)
	if err != nil {
		return nil, err
	}
	if sub == "" {
		return nil, errors.New("kök anahtara doğrudan değer yazılamaz")
	}
	k, _, err := registry.CreateKey(root, sub, registry.SET_VALUE|registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil, fmt.Errorf("anahtar açılamadı: %w", err)
	}
	defer k.Close()
	change := &protocol.RegistryChange{}
	if prev, err := readValue(k, v.Name); err == nil {
		change.Previous = prev
	}
	switch v.Type {
	case "REG_SZ":
		err = k.SetStringValue(v.Name, v.Data)
	case "REG_EXPAND_SZ":
		err = k.SetExpandStringValue(v.Name, v.Data)
	case "REG_MULTI_SZ":
		err = k.SetStringsValue(v.Name, strings.Split(strings.ReplaceAll(v.Data, "\r\n", "\n"), "\n"))
	case "REG_DWORD":
		var n uint64
		if n, err = strconv.ParseUint(strings.TrimSpace(v.Data), 0, 32); err == nil {
			err = k.SetDWordValue(v.Name, uint32(n))
		}
	case "REG_QWORD":
		var n uint64
		if n, err = strconv.ParseUint(strings.TrimSpace(v.Data), 0, 64); err == nil {
			err = k.SetQWordValue(v.Name, n)
		}
	case "REG_BINARY":
		var b []byte
		if b, err = hex.DecodeString(strings.ReplaceAll(v.Data, " ", "")); err == nil {
			err = k.SetBinaryValue(v.Name, b)
		}
	default:
		return nil, fmt.Errorf("desteklenmeyen tür: %s", v.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("değer yazılamadı: %w", err)
	}
	return change, nil
}

// RegistryDelete, değeri siler ve önceki değeri döner.
func RegistryDelete(path, name string) (*protocol.RegistryChange, error) {
	k, err := openKey(path, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("anahtar açılamadı: %w", err)
	}
	defer k.Close()
	change := &protocol.RegistryChange{}
	prev, err := readValue(k, name)
	if err != nil {
		return nil, fmt.Errorf("değer bulunamadı: %w", err)
	}
	change.Previous = prev
	if err := k.DeleteValue(name); err != nil {
		return nil, fmt.Errorf("değer silinemedi: %w", err)
	}
	return change, nil
}
