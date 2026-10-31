package auth

// Permission, sunucu tarafında her uç noktada kontrol edilen granüler yetkidir.
// Yeni izinler eklenebilir; mevcut izin adları değiştirilmez (özel roller bunlara bağlanır).
type Permission string

// İzinler.
const (
	PermMachinesRead   Permission = "machines.read"
	PermMachinesManage Permission = "machines.manage" // onay, reddetme, silme, etiketleme

	PermReportsRead   Permission = "reports.read"
	PermReportsExport Permission = "reports.export"

	PermPackagesRead   Permission = "packages.read"
	PermPackagesUpload Permission = "packages.upload"
	PermPackagesDelete Permission = "packages.delete"

	PermActionsDeployPackage Permission = "actions.deploy_package" // kayıtlı paket gönderme
	PermActionsDeployPatch   Permission = "actions.deploy_patch"
	PermActionsRunCommand    Permission = "actions.run_command" // serbest komut / dosya + komut
	PermActionsApprove       Permission = "actions.approve"     // dört göz onayı

	PermRemotePerformance   Permission = "remote.performance"
	PermRemoteServices      Permission = "remote.services"
	PermRemoteRegistryRead  Permission = "remote.registry.read"
	PermRemoteRegistryWrite Permission = "remote.registry.write"
	PermRemoteSettings      Permission = "remote.settings" // opt-in ayarlarını açma/kapama

	PermSettingsRead    Permission = "settings.read"
	PermSettingsWrite   Permission = "settings.write"
	PermUsersManage     Permission = "users.manage"
	PermADConfigure     Permission = "ad.configure"
	PermRegKeysManage   Permission = "regkeys.manage"
	PermAuditRead       Permission = "audit.read"
	PermRateLimitManage Permission = "transfer.limits.manage"
)

// Role, yerleşik rol adıdır. Aşama 5'te veritabanında tanımlı özel roller eklenecek.
type Role string

// Yerleşik roller.
const (
	RoleAdmin      Role = "admin"
	RoleTechnician Role = "technician"
	RoleReadOnly   Role = "readonly"
)

// readPermissions, değişiklik yapmayan ve tüm rollerin sahip olduğu izinlerdir.
var readPermissions = []Permission{
	PermMachinesRead,
	PermReportsRead,
	PermReportsExport,
	PermPackagesRead,
	PermSettingsRead,
	PermAuditRead,
}

// AllPermissions, tanımlı tüm izinlerdir (admin rolü ve testler için).
var AllPermissions = []Permission{
	PermMachinesRead, PermMachinesManage,
	PermReportsRead, PermReportsExport,
	PermPackagesRead, PermPackagesUpload, PermPackagesDelete,
	PermActionsDeployPackage, PermActionsDeployPatch, PermActionsRunCommand, PermActionsApprove,
	PermRemotePerformance, PermRemoteServices, PermRemoteRegistryRead, PermRemoteRegistryWrite, PermRemoteSettings,
	PermSettingsRead, PermSettingsWrite, PermUsersManage, PermADConfigure, PermRegKeysManage, PermAuditRead,
	PermRateLimitManage,
}

var rolePermissions = map[Role]map[Permission]bool{
	RoleAdmin:      set(AllPermissions...),
	RoleTechnician: set(append([]Permission{PermActionsDeployPackage}, readPermissions...)...),
	RoleReadOnly:   set(readPermissions...),
}

func set(perms ...Permission) map[Permission]bool {
	m := make(map[Permission]bool, len(perms))
	for _, p := range perms {
		m[p] = true
	}
	return m
}

// ValidRole, rol adının tanımlı olup olmadığını döner.
func ValidRole(r Role) bool {
	_, ok := rolePermissions[r]
	return ok
}

// HasPermission, rolün izne sahip olup olmadığını döner. Bilinmeyen roller hiçbir izne sahip değildir.
func HasPermission(r Role, p Permission) bool {
	return rolePermissions[r][p]
}

// PermissionsOf, rolün izinlerini AllPermissions sırasıyla döner (konsol arayüzü için).
func PermissionsOf(r Role) []Permission {
	out := []Permission{}
	for _, p := range AllPermissions {
		if rolePermissions[r][p] {
			out = append(out, p)
		}
	}
	return out
}
