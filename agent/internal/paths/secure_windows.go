//go:build windows

package paths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// dataDirSDDL, veri dizininin izin listesidir: yalnızca SYSTEM ve Administrators tam yetkili,
// üst dizinden (ProgramData; Users okuma ve oluşturma hakkına sahiptir) miras alınmaz.
const dataDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// Secure, veri dizinini standart kullanıcıların okuyamayacağı ve yazamayacağı hâle getirir.
// Dizindeki her girişin sahibi Administrators yapılır ve açık izinleri silinip yalnızca
// dizinden miras alınır; bunun yapılamadığı girişler (ör. kullanıcının önceden yerleştirdiği
// ve SYSTEM'e kapattığı) ile bağlantılar (symlink/junction) silinir. Ajan servisi (SYSTEM)
// her açılışta çağırır.
func Secure(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Başkasına ait girişlerin sahipliğini almak için gerekir (SYSTEM'de vardır, kapalı olabilir).
	enablePrivileges("SeTakeOwnershipPrivilege", "SeRestorePrivilege")
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(dataDirSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		admins, nil, dacl, nil); err != nil {
		return err
	}
	inherit, err := windows.ACLFromEntries(nil, nil)
	if err != nil {
		return err
	}
	var errs []error
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if path == dir {
			return err
		}
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		if d.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			// Ajan bağlantı oluşturmaz; dizin dışına yönlendirme girişimi kaldırılır.
			errs = append(errs, os.Remove(path))
			return nil
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
			admins, nil, inherit, nil); err != nil {
			if trustedOwner(path) {
				// Ajanın kendi dosyası (ör. o an kilitli): silinmez, hata bildirilir.
				errs = append(errs, err)
				return nil
			}
			errs = append(errs, os.RemoveAll(path))
			if d.IsDir() {
				return fs.SkipDir
			}
		}
		return nil
	})
	return errors.Join(append(errs, walkErr)...)
}

// trustedOwner, girişin sahibinin SYSTEM veya Administrators olup olmadığını döner.
func trustedOwner(path string) bool {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false
	}
	return owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

// enablePrivileges, süreç belirtecindeki ayrıcalıkları açmayı dener (en iyi çaba).
func enablePrivileges(names ...string) {
	var tok windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok) != nil {
		return
	}
	defer tok.Close()
	for _, n := range names {
		var luid windows.LUID
		if windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(n), &luid) != nil {
			continue
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		_ = windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
	}
}
