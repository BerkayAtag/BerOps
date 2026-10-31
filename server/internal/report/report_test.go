package report

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"testing"
	"time"
)

func sample() *Table {
	at := time.Date(2026, 10, 31, 9, 30, 0, 0, time.UTC)
	ist, _ := time.LoadLocation("Europe/Istanbul")
	score := float32(9.8)
	return &Table{
		Title: "Zafiyet Raporu — Şube İzmir", Subtitle: "Önem: Kritik", GeneratedAt: at, GeneratedBy: "ayşe",
		Lang: "tr", Location: ist,
		Summary: []Metric{{Label: "Toplam CVE", Value: "42"}, {Label: "KEV", Value: "3"}},
		Columns: []Column{
			{Header: "CVE", Width: 16}, {Header: "Başlık", Width: 40}, {Header: "CVSS", Width: 6, Kind: Decimal},
			{Header: "EPSS", Width: 8, Kind: Percent}, {Header: "Makine", Width: 8, Kind: Number},
			{Header: "Yayın", Width: 14, Kind: DateTime}, {Header: "KEV", Width: 6},
		},
		Rows: [][]any{
			{"CVE-2026-0001", "Uzaktan kod çalıştırma — ğüşıöç ĞÜŞİÖÇ", &score, 0.9731, 12, at, true},
			{"CVE-2026-0002", "=HYPERLINK(\"http://kötü\")", nil, nil, 1, nil, false},
		},
	}
}

func TestCSV(t *testing.T) {
	var b bytes.Buffer
	if err := WriteCSV(&b, sample()); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	if !strings.HasPrefix(s, "\xef\xbb\xbf") {
		t.Error("CSV UTF-8 BOM ile başlamalı")
	}
	for _, want := range []string{
		"CVE,Başlık,CVSS,EPSS,Makine,Yayın,KEV",
		"CVE-2026-0001,Uzaktan kod çalıştırma — ğüşıöç ĞÜŞİÖÇ,9.8,0.97310,12,2026-10-31 12:30,Evet",
		`"'=HYPERLINK(""http://kötü"")"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("CSV içinde %q yok:\n%s", want, s)
		}
	}
}

func TestXLSX(t *testing.T) {
	var b bytes.Buffer
	if err := WriteXLSX(&b, sample()); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(b.Bytes()), int64(b.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var sheet string
	for _, f := range zr.File {
		rc, _ := f.Open()
		body, _ := io.ReadAll(rc)
		rc.Close()
		// Her parça iyi biçimli XML olmalı.
		dec := xml.NewDecoder(bytes.NewReader(body))
		for {
			if _, err := dec.Token(); err == io.EOF {
				break
			} else if err != nil {
				t.Fatalf("%s geçersiz XML: %v", f.Name, err)
			}
		}
		if f.Name == "xl/worksheets/sheet1.xml" {
			sheet = string(body)
		}
	}
	for _, want := range []string{
		`<c r="A5" t="inlineStr" s="0"><is><t xml:space="preserve">CVE-2026-0001</t></is></c>`,
		`<c r="C5" s="3"><v>9.8`,
		`<c r="D5" s="4"><v>0.9731</v></c>`,
		`<c r="E5" s="0"><v>12</v></c>`,
		`<autoFilter ref="A4:G6"/>`,
		`ğüşıöç ĞÜŞİÖÇ`,
	} {
		if !strings.Contains(sheet, want) {
			t.Errorf("sayfada %q yok", want)
		}
	}
	// 2026-10-31 12:30 (İstanbul) Excel seri numarası: 46326.520833…
	if !strings.Contains(sheet, `<c r="F5" s="2"><v>46326.52083`) {
		t.Errorf("tarih seri numarası hatalı:\n%s", sheet)
	}
}

func TestPDF(t *testing.T) {
	var b bytes.Buffer
	tb := sample()
	for i := range 300 {
		tb.Rows = append(tb.Rows, []any{"CVE-2026-1" + string(rune('0'+i%10)), "satır", nil, nil, i, nil, false})
	}
	if err := WritePDF(&b, tb); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b.Bytes(), []byte("%PDF-")) || b.Len() < 10_000 {
		t.Fatalf("geçersiz PDF (%d bayt)", b.Len())
	}
}

func TestCellRef(t *testing.T) {
	for want, in := range map[string][2]int{"A1": {0, 1}, "Z3": {25, 3}, "AA10": {26, 10}, "AZ2": {51, 2}} {
		if got := cellRef(in[0], in[1]); got != want {
			t.Errorf("cellRef(%v) = %s, beklenen %s", in, got, want)
		}
	}
}
