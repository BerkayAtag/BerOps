package report

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

// Excel stil indeksleri (styles.xml içindeki cellXfs sırası).
const (
	styleDefault = 0
	styleHeader  = 1
	styleDate    = 2
	styleDecimal = 3
	stylePercent = 4
	styleDay     = 5
	styleTitle   = 6
)

const stylesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<numFmts count="3"><numFmt numFmtId="164" formatCode="yyyy-mm-dd hh:mm"/><numFmt numFmtId="165" formatCode="0.0"/><numFmt numFmtId="166" formatCode="yyyy-mm-dd"/></numFmts>
<fonts count="3"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font><font><b/><sz val="14"/><name val="Calibri"/></font></fonts>
<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FFDC0005"/><bgColor indexed="64"/></patternFill></fill></fills>
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="7">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>
<xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>
<xf numFmtId="165" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>
<xf numFmtId="10" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>
<xf numFmtId="166" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>
<xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/>
</cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>`

// WriteXLSX, tek sayfalık Excel çalışma kitabı yazar: başlık satırları, kırmızı sütun
// başlıkları, dondurulmuş başlık satırı ve otomatik filtre. Harici kütüphane kullanılmaz.
func WriteXLSX(w io.Writer, t *Table) error {
	zw := zip.NewWriter(w)
	files := []struct{ name, body string }{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>`},
		{"docProps/core.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:title>` + esc(t.Title) + `</dc:title><dc:creator>BerOps</dc:creator>
<dcterms:created xsi:type="dcterms:W3CDTF">` + t.GeneratedAt.UTC().Format(time.RFC3339) + `</dcterms:created>
</cp:coreProperties>`},
		{"xl/workbook.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="` + esc(sheetName(t.Title)) + `" sheetId="1" r:id="rId1"/></sheets>
</workbook>`},
		{"xl/_rels/workbook.xml.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>`},
		{"xl/styles.xml", stylesXML},
	}
	for _, f := range files {
		fw, err := zw.Create(f.name)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(fw, f.body); err != nil {
			return err
		}
	}
	fw, err := zw.Create("xl/worksheets/sheet1.xml")
	if err != nil {
		return err
	}
	if err := writeSheet(fw, t); err != nil {
		return err
	}
	return zw.Close()
}

// headerRow, sütun başlıklarının satır numarasıdır (1: başlık, 2: alt başlık, 3: boş).
const headerRow = 4

func writeSheet(w io.Writer, t *Table) error {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	b.WriteString(`<sheetViews><sheetView workbookViewId="0"><pane ySplit="` + strconv.Itoa(headerRow) +
		`" topLeftCell="A` + strconv.Itoa(headerRow+1) + `" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>`)
	b.WriteString(`<cols>`)
	for i, c := range t.Columns {
		width := math.Max(8, math.Min(80, c.Width*1.15))
		fmt.Fprintf(&b, `<col min="%d" max="%d" width="%.1f" customWidth="1"/>`, i+1, i+1, width)
	}
	b.WriteString(`</cols><sheetData>`)
	if _, err := io.WriteString(w, b.String()); err != nil {
		return err
	}
	b.Reset()

	sub := t.Subtitle
	meta := tr(t.Lang, "generated") + ": " + t.GeneratedAt.In(t.loc()).Format("2006-01-02 15:04")
	if t.GeneratedBy != "" {
		meta += " · " + tr(t.Lang, "by") + ": " + t.GeneratedBy
	}
	if sub != "" {
		meta = sub + " · " + meta
	}
	fmt.Fprintf(&b, `<row r="1">%s</row><row r="2">%s</row>`, strCell("A1", t.Title, styleTitle), strCell("A2", meta, styleDefault))
	b.WriteString(`<row r="` + strconv.Itoa(headerRow) + `">`)
	for i, c := range t.Columns {
		b.WriteString(strCell(cellRef(i, headerRow), c.Header, styleHeader))
	}
	b.WriteString(`</row>`)
	for r, row := range t.Rows {
		rn := headerRow + 1 + r
		b.WriteString(`<row r="` + strconv.Itoa(rn) + `">`)
		for i, c := range t.Columns {
			var v any
			if i < len(row) {
				v = row[i]
			}
			b.WriteString(t.xlsxCell(cellRef(i, rn), v, c.Kind))
		}
		b.WriteString(`</row>`)
		if b.Len() > 64<<10 {
			if _, err := io.WriteString(w, b.String()); err != nil {
				return err
			}
			b.Reset()
		}
	}
	b.WriteString(`</sheetData>`)
	if len(t.Columns) > 0 {
		last := headerRow + len(t.Rows)
		fmt.Fprintf(&b, `<autoFilter ref="A%d:%s"/>`, headerRow, cellRef(len(t.Columns)-1, last))
	}
	b.WriteString(`<pageSetup orientation="landscape" fitToWidth="1" fitToHeight="0"/></worksheet>`)
	_, err := io.WriteString(w, b.String())
	return err
}

// excelEpoch, Excel tarih seri numaralarının başlangıcıdır (1900 artık yıl hatası dahil).
var excelEpoch = time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC)

func (t *Table) xlsxCell(ref string, v any, k Kind) string {
	num := func(f float64, style int) string {
		return fmt.Sprintf(`<c r="%s" s="%d"><v>%s</v></c>`, ref, style, strconv.FormatFloat(f, 'f', -1, 64))
	}
	switch x := v.(type) {
	case nil:
		return ""
	case int:
		return num(float64(x), styleDefault)
	case int64:
		return num(float64(x), styleDefault)
	case float32:
		return t.xlsxCell(ref, float64(x), k)
	case *float32:
		if x == nil {
			return ""
		}
		return t.xlsxCell(ref, float64(*x), k)
	case float64:
		switch k {
		case Percent:
			return num(x, stylePercent)
		case Decimal:
			return num(x, styleDecimal)
		}
		return num(x, styleDefault)
	case time.Time:
		if x.IsZero() {
			return ""
		}
		// Yerel saat, Excel'in saat dilimi kavramı olmadığından duvar saati olarak yazılır.
		l := x.In(t.loc())
		wall := time.Date(l.Year(), l.Month(), l.Day(), l.Hour(), l.Minute(), l.Second(), 0, time.UTC)
		serial := wall.Sub(excelEpoch).Hours() / 24
		if k == Date {
			return num(math.Floor(serial), styleDay)
		}
		return num(serial, styleDate)
	case *time.Time:
		if x == nil {
			return ""
		}
		return t.xlsxCell(ref, *x, k)
	}
	return strCell(ref, t.text(v, k), styleDefault)
}

func strCell(ref, s string, style int) string {
	if s == "" {
		return ""
	}
	if len(s) > 32000 {
		s = s[:32000]
	}
	return fmt.Sprintf(`<c r="%s" t="inlineStr" s="%d"><is><t xml:space="preserve">%s</t></is></c>`, ref, style, esc(s))
}

func esc(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// cellRef, sıfır tabanlı sütun ve bir tabanlı satırdan "A1" biçimli başvuru üretir.
func cellRef(col, row int) string {
	name := ""
	for col >= 0 {
		name = string(rune('A'+col%26)) + name
		col = col/26 - 1
	}
	return name + strconv.Itoa(row)
}

// sheetName, Excel sayfa adı kurallarına uyar (en fazla 31 karakter, []:*?/\ yasak).
func sheetName(s string) string {
	s = strings.Map(func(r rune) rune {
		if strings.ContainsRune(`[]:*?/\`, r) {
			return '-'
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 31 {
		s = string(r[:31])
	}
	if s == "" {
		return "Rapor"
	}
	return s
}
