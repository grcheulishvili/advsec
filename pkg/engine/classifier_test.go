package engine

import (
	"testing"

	"github.com/grcheulishvili/advsec/pkg/plugin"
)

func TestClassifyMagicBytes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Format
	}{
		{"elf", "\x7fELF\x02\x01\x01", FormatELF},
		{"pe", "MZ\x90\x00\x03", FormatPE},
		{"macho", "\xcf\xfa\xed\xfe\x07", FormatMachO},
		{"zip", "PK\x03\x04\x14", FormatZip},
		{"gzip", "\x1f\x8b\x08\x00", FormatGzip},
		{"7z", "7z\xbc\xaf\x27\x1c", Format7z},
		{"pdf", "%PDF-1.7", FormatPDF},
		{"pcap", "\xd4\xc3\xb2\xa1\x02\x00", FormatPcap},
	}
	for _, c := range cases {
		if got := Classify(c.in); got != c.want {
			t.Errorf("%s: Classify = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestClassifyEmail(t *testing.T) {
	eml := "Received: from mx.evil.test\r\nFrom: ceo@victim.test\r\nSubject: Invoice\r\nMIME-Version: 1.0\r\n\r\nbody"
	if got := Classify(eml); got != FormatEmail {
		t.Fatalf("Classify = %q, want email/mime", got)
	}
}

func TestClassifyLogAndText(t *testing.T) {
	if got := Classify("Oct 05 10:00:01 host sshd[1]: Failed password"); got != FormatLog {
		t.Errorf("syslog classify = %q, want text/log", got)
	}
	if got := Classify("just some words with no structure"); got != FormatText {
		t.Errorf("plain classify = %q, want text/plain", got)
	}
}

func TestFilterByFormatEmailScopesToEml(t *testing.T) {
	plugins := []plugin.Plugin{
		{ID: "eml-x", Domain: "eml"},
		{ID: "kerb", Domain: "redteam"},
		{ID: "dock", Domain: "cloud"},
		{ID: "sdr", Domain: "wireless"},
		{ID: "hash", Domain: "general"},
	}
	got := FilterByFormat(plugins, FormatEmail)
	if len(got) != 1 || got[0].ID != "eml-x" {
		t.Fatalf("email scope should keep only eml plugins, got %+v", got)
	}
}

func TestFilterByFormatTextNoRestriction(t *testing.T) {
	plugins := []plugin.Plugin{{ID: "a", Domain: "web"}, {ID: "b", Domain: "pwn"}}
	if got := FilterByFormat(plugins, FormatText); len(got) != 2 {
		t.Fatalf("text/plain should impose no restriction, got %d", len(got))
	}
}

// Regression: a raw email must not surface Kerberoasting/Docker/SDR etc.
func TestEmailDoesNotTriggerUnrelatedRules(t *testing.T) {
	res := plugin.LoadFromDirs([]string{"../../plugins"})
	eml := "Received: from mx.test\r\nDKIM-Signature: v=1; b=" +
		"aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkMTIzNDU2Nzg5MA==\r\n" +
		"From: a@b.test\r\nSubject: hi\r\nX-Originating-IP: 10.0.0.5\r\n\r\nvisit http://evil.test\r\n"
	ctx := ParseString(eml)
	if ctx.Format != FormatEmail {
		t.Fatalf("expected email classification, got %q", ctx.Format)
	}
	scoped := FilterByFormat(res.Plugins, ctx.Format)
	matches := NewMatcher(scoped).Evaluate(ctx)
	// Email scopes to {eml, crypto}; the offensive/infra domains must never fire.
	suppressed := map[string]bool{"network": true, "redteam": true, "cloud": true,
		"wireless": true, "pwn": true, "reversing": true, "mobile": true}
	for _, m := range matches {
		if suppressed[m.Plugin.Domain] {
			t.Errorf("email input surfaced suppressed rule %q (domain %q)", m.Plugin.ID, m.Plugin.Domain)
		}
	}
}
