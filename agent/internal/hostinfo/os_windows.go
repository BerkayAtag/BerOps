//go:build windows

package hostinfo

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// readOSInfo, sürüm bilgisini kayıt defterinden okur. ProductName Windows 11'de de
// "Windows 10" döndüğü için ad derleme numarasına göre düzeltilir (22000 ve üzeri = Windows 11).
func readOSInfo() OSInfo {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return OSInfo{Name: "Windows"}
	}
	defer k.Close()

	str := func(name string) string {
		v, _, _ := k.GetStringValue(name)
		return v
	}
	num := func(name string) uint64 {
		v, _, _ := k.GetIntegerValue(name)
		return v
	}

	name := str("ProductName")
	buildStr := str("CurrentBuildNumber")
	build, _ := strconv.Atoi(buildStr)
	if build >= 22000 {
		name = strings.Replace(name, "Windows 10", "Windows 11", 1)
	}
	ver := str("DisplayVersion")
	if ver == "" {
		ver = str("ReleaseId")
	}
	major, minor := num("CurrentMajorVersionNumber"), num("CurrentMinorVersionNumber")
	if major == 0 {
		major, minor = 10, 0
	}
	return OSInfo{
		Name:    name,
		Version: ver,
		Build:   fmt.Sprintf("%d.%d.%s.%d", major, minor, buildStr, num("UBR")),
	}
}
