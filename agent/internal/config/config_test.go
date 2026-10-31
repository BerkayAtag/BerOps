package config

import (
	"strings"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := Config{ServerURL: "https://ber.example.test:52311", CAHash: "sha256:ab", RegistrationKey: "berreg_x"}
	if err := Save(dir, in); err != nil {
		t.Fatal(err)
	}
	out, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Errorf("okunan yapılandırma farklı: %+v", out)
	}
}

func TestLoadMissingGivesHelpfulError(t *testing.T) {
	_, err := Load(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "ber-agent enroll") {
		t.Fatalf("yardımcı hata mesajı beklenirdi: %v", err)
	}
}

func TestValidate(t *testing.T) {
	for _, c := range []Config{
		{ServerURL: "http://ber:52311", CAHash: "x"},
		{ServerURL: "https://", CAHash: "x"},
		{ServerURL: "https://ber:52311"},
	} {
		if err := c.Validate(); err == nil {
			t.Errorf("%+v reddedilmeli", c)
		}
	}
}
