package report

import (
	"fmt"
	"io"

	"github.com/go-pdf/fpdf"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/gofont/goregular"
)

// Marka renkleri (design/tokens.css ile aynı).
var (
	brandRed  = [3]int{0xdc, 0x00, 0x05}
	textDark  = [3]int{0x1f, 0x23, 0x28}
	textMuted = [3]int{0x5f, 0x66, 0x6d}
	zebra     = [3]int{0xf5, 0xf6, 0xf7}
	cardFill  = [3]int{0xfa, 0xfa, 0xfb}
)

// MaxPDFRows, PDF'e yazılan en fazla satırdır; daha büyük raporlar Excel/CSV ile alınmalıdır.
const MaxPDFRows = 5000

const fontFamily = "go"

// WritePDF, A4 yatay PDF rapor yazar. Türkçe karakterler için Go yazı tipi gömülür.
func WritePDF(w io.Writer, t *Table) error {
	pdf := fpdf.New("L", "mm", "A4", "")
	pdf.SetCreator("Automation BER", true)
	pdf.SetTitle(t.Title, true)
	pdf.SetAuthor("Automation BER", true)
	pdf.AddUTF8FontFromBytes(fontFamily, "", goregular.TTF)
	pdf.AddUTF8FontFromBytes(fontFamily, "B", gobold.TTF)
	pdf.SetMargins(12, 14, 12)
	pdf.SetAutoPageBreak(true, 14)
	pdf.AliasNbPages("{nb}")

	pageW, _ := pdf.GetPageSize()
	left, _, right, _ := pdf.GetMargins()
	contentW := pageW - left - right

	pdf.SetHeaderFunc(func() {
		pdf.SetFillColor(brandRed[0], brandRed[1], brandRed[2])
		pdf.Rect(0, 0, pageW, 4, "F")
	})
	pdf.SetFooterFunc(func() {
		pdf.SetY(-10)
		pdf.SetFont(fontFamily, "", 8)
		pdf.SetTextColor(textMuted[0], textMuted[1], textMuted[2])
		pdf.CellFormat(contentW/2, 5, "Automation BER · "+t.Title, "", 0, "L", false, 0, "")
		pdf.CellFormat(contentW/2, 5, fmt.Sprintf("%s %d / {nb}", tr(t.Lang, "page"), pdf.PageNo()), "", 0, "R", false, 0, "")
	})

	pdf.AddPage()
	pdf.SetTextColor(textDark[0], textDark[1], textDark[2])
	pdf.SetFont(fontFamily, "B", 18)
	pdf.CellFormat(contentW, 9, t.Title, "", 1, "L", false, 0, "")
	pdf.SetFont(fontFamily, "", 9)
	pdf.SetTextColor(textMuted[0], textMuted[1], textMuted[2])
	meta := tr(t.Lang, "generated") + ": " + t.GeneratedAt.In(t.loc()).Format("2006-01-02 15:04")
	if t.GeneratedBy != "" {
		meta += "   ·   " + tr(t.Lang, "by") + ": " + t.GeneratedBy
	}
	meta += fmt.Sprintf("   ·   %s: %d", tr(t.Lang, "rows"), len(t.Rows))
	pdf.CellFormat(contentW, 5, meta, "", 1, "L", false, 0, "")
	if t.Subtitle != "" {
		pdf.CellFormat(contentW, 5, tr(t.Lang, "filters")+": "+t.Subtitle, "", 1, "L", false, 0, "")
	}
	pdf.Ln(3)

	if n := len(t.Summary); n > 0 {
		gap := 3.0
		boxW := (contentW - gap*float64(n-1)) / float64(n)
		y := pdf.GetY()
		for i, m := range t.Summary {
			x := left + float64(i)*(boxW+gap)
			pdf.SetFillColor(cardFill[0], cardFill[1], cardFill[2])
			pdf.SetDrawColor(0xe3, 0xe5, 0xe8)
			pdf.Rect(x, y, boxW, 16, "FD")
			pdf.SetFillColor(brandRed[0], brandRed[1], brandRed[2])
			pdf.Rect(x, y, 1.2, 16, "F")
			pdf.SetXY(x+3, y+2)
			pdf.SetFont(fontFamily, "", 8)
			pdf.SetTextColor(textMuted[0], textMuted[1], textMuted[2])
			pdf.CellFormat(boxW-4, 4, fit(pdf, m.Label, boxW-4), "", 0, "L", false, 0, "")
			pdf.SetXY(x+3, y+7)
			pdf.SetFont(fontFamily, "B", 13)
			pdf.SetTextColor(textDark[0], textDark[1], textDark[2])
			pdf.CellFormat(boxW-4, 7, fit(pdf, m.Value, boxW-4), "", 0, "L", false, 0, "")
		}
		pdf.SetY(y + 20)
	}

	var total float64
	for _, c := range t.Columns {
		total += c.Width
	}
	widths := make([]float64, len(t.Columns))
	for i, c := range t.Columns {
		widths[i] = contentW * c.Width / total
	}
	const rowH = 6.0
	header := func() {
		pdf.SetFont(fontFamily, "B", 8)
		pdf.SetFillColor(brandRed[0], brandRed[1], brandRed[2])
		pdf.SetTextColor(255, 255, 255)
		for i, c := range t.Columns {
			pdf.CellFormat(widths[i], rowH+1, fit(pdf, c.Header, widths[i]-2), "", 0, align(c.Kind), true, 0, "")
		}
		pdf.Ln(-1)
		pdf.SetFont(fontFamily, "", 8)
		pdf.SetTextColor(textDark[0], textDark[1], textDark[2])
	}
	header()
	_, pageH := pdf.GetPageSize()
	rows := t.Rows
	if len(rows) > MaxPDFRows {
		rows = rows[:MaxPDFRows]
	}
	for r, row := range rows {
		if pdf.GetY()+rowH > pageH-16 {
			pdf.AddPage()
			header()
		}
		fill := r%2 == 1
		pdf.SetFillColor(zebra[0], zebra[1], zebra[2])
		for i, c := range t.Columns {
			var v any
			if i < len(row) {
				v = row[i]
			}
			pdf.CellFormat(widths[i], rowH, fit(pdf, t.text(v, c.Kind), widths[i]-2), "", 0, align(c.Kind), fill, 0, "")
		}
		pdf.Ln(-1)
	}
	if t.Note != "" {
		pdf.Ln(3)
		pdf.SetFont(fontFamily, "", 8)
		pdf.SetTextColor(textMuted[0], textMuted[1], textMuted[2])
		pdf.MultiCell(contentW, 4, t.Note, "", "L", false)
	}
	if err := pdf.Error(); err != nil {
		return err
	}
	return pdf.Output(w)
}

func align(k Kind) string {
	switch k {
	case Number, Decimal, Percent:
		return "R"
	}
	return "L"
}

// fit, metni hücre genişliğine sığacak şekilde "…" ile kısaltır.
func fit(pdf *fpdf.Fpdf, s string, w float64) string {
	if pdf.GetStringWidth(s) <= w {
		return s
	}
	r := []rune(s)
	lo, hi := 0, len(r)
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if pdf.GetStringWidth(string(r[:mid])+"…") <= w {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return string(r[:lo]) + "…"
}
