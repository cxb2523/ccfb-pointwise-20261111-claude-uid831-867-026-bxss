package arguments

import (
	"strings"
	"testing"
)

func TestParseContext(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    Context
		wantErr bool
	}{
		{name: "default empty is html", raw: "", want: ContextHTML},
		{name: "whitespace only is html", raw: "   ", want: ContextHTML},
		{name: "html", raw: "html", want: ContextHTML},
		{name: "js", raw: "js", want: ContextJS},
		{name: "attribute", raw: "attribute", want: ContextAttribute},
		{name: "uri", raw: "uri", want: ContextURI},
		{name: "case and whitespace tolerated", raw: "  JS  ", want: ContextJS},
		{name: "unknown value", raw: "css", wantErr: true},
		{name: "typo", raw: "htm", wantErr: true},
		{name: "scheme name is not a context", raw: "javascript", wantErr: true},
		{name: "empty-ish token", raw: "-", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseContext(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseContext(%q) expected error, got %q", tt.raw, got)
				}
				// An invalid value must be reported together with every
				// supported value; no silent fallback.
				for _, valid := range ContextValues {
					if !strings.Contains(err.Error(), string(valid)) {
						t.Fatalf("error %q does not list supported value %q", err.Error(), valid)
					}
				}
				if strings.Contains(err.Error(), string(got)) && got != "" {
					t.Fatalf("error should not echo a coerced default context: %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseContext(%q) unexpected error: %v", tt.raw, err)
			}
			if got != tt.want {
				t.Fatalf("ParseContext(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestContextValuesAreTheSupportedEnum(t *testing.T) {
	want := map[Context]bool{
		ContextHTML:      true,
		ContextJS:        true,
		ContextAttribute: true,
		ContextURI:       true,
	}
	if len(ContextValues) != len(want) {
		t.Fatalf("ContextValues has %d entries, want %d", len(ContextValues), len(want))
	}
	for _, value := range ContextValues {
		if !want[value] {
			t.Fatalf("unexpected context value %q", value)
		}
		// Every enum value must parse back to itself.
		parsed, err := ParseContext(string(value))
		if err != nil || parsed != value {
			t.Fatalf("enum value %q did not round-trip through ParseContext: got %q, err %v", value, parsed, err)
		}
	}
}
