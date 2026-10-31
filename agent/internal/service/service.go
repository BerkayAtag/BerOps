// Package service, ajanın işletim sistemi servis yöneticisi altında çalışmasını sağlar.
// Windows'ta Servis Denetim Yöneticisi (SCM) ile konuşur; macOS'ta launchd süreci
// doğrudan başlattığı için ek bir şey gerekmez.
package service

// Name, Windows servis adıdır.
const Name = "BERAgent"
