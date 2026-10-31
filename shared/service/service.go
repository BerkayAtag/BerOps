// Package service, ajanın ve sunucunun işletim sistemi servis yöneticisi altında
// çalışmasını sağlar. Windows'ta Servis Denetim Yöneticisi (SCM) ile konuşur; macOS ve
// Linux'ta launchd/systemd süreci doğrudan başlattığı için ek bir şey gerekmez.
package service

// Windows servis adları.
const (
	AgentName  = "BerOpsAgent"
	ServerName = "BerOpsServer"
)
