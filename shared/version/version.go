// Package version, derleme sırasında -ldflags ile doldurulan sürüm bilgisini taşır.
//
//	go build -ldflags "-X github.com/BerkayAtag/automation-ber/shared/version.Version=1.2.3"
package version

// Version, semantik sürüm numarasıdır. Geliştirme derlemelerinde "0.0.0-dev" olarak kalır.
var Version = "0.0.0-dev"

// Commit, derlemenin yapıldığı git commit özetidir.
var Commit = "unknown"
