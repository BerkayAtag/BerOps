package protocol

import (
	"testing"
	"time"
)

func TestHashSectionIsStableAndSensitive(t *testing.T) {
	a := []App{{Name: "7-Zip", Version: "23.01", Source: AppSourceMSI}}
	b := []App{{Name: "7-Zip", Version: "24.08", Source: AppSourceMSI}}
	if HashSection(a) != HashSection([]App{{Name: "7-Zip", Version: "23.01", Source: AppSourceMSI}}) {
		t.Error("aynı içerik aynı özeti vermeli")
	}
	if HashSection(a) == HashSection(b) {
		t.Error("sürüm değişikliği özeti değiştirmeli")
	}
}

func TestReportValidate(t *testing.T) {
	ok := InventoryReport{Included: []string{SectionApps}, Apps: []App{}}
	if err := ok.Validate(); err != nil {
		t.Errorf("geçerli rapor reddedildi: %v", err)
	}
	for name, r := range map[string]InventoryReport{
		"bilinmeyen bölüm":   {Included: []string{"registry"}},
		"os içeriksiz":       {Included: []string{SectionOS}},
		"tarama bilgisi yok": {Included: []string{SectionMissingPatches}},
		"çok büyük":          {Included: []string{SectionApps}, Apps: make([]App, 20001)},
	} {
		if err := r.Validate(); err == nil {
			t.Errorf("%s reddedilmeli", name)
		}
	}
	full := InventoryReport{Included: []string{SectionMissingPatches}, MissingScan: &MissingScanInfo{Source: ScanSourceOnline, ScannedAt: time.Now()}}
	if err := full.Validate(); err != nil {
		t.Error(err)
	}
}

func TestAgentSettingsValidate(t *testing.T) {
	if err := DefaultAgentSettings().Validate(); err != nil {
		t.Fatalf("varsayılanlar geçerli olmalı: %v", err)
	}
	s := DefaultAgentSettings()
	s.DeltaScanIntervalHours = 48
	s.ScanCPULimitPercent = 0
	s.WindowsUpdateSource = "internet"
	if err := s.Validate(); err == nil {
		t.Fatal("geçersiz ayarlar reddedilmeli")
	}
}
