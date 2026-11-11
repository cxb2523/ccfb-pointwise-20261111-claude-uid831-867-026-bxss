package arguments

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ethicalhackingplayground/bxss/v2/pkg/colours"
)

// Context selects how a blind XSS callback is encoded to survive the
// injection point it is placed into.
type Context string

const (
	// ContextHTML injects into raw HTML text/markup. The payload is emitted
	// byte-for-byte unchanged so tag injection keeps working.
	ContextHTML Context = "html"
	// ContextJS injects into a JavaScript string or script block.
	ContextJS Context = "js"
	// ContextAttribute injects into a quoted HTML attribute.
	ContextAttribute Context = "attribute"
	// ContextURI injects into a navigable position such as an href/src
	// attribute, producing a javascript: URI.
	ContextURI Context = "uri"
)

// ContextValues lists every supported --context value. It is the single
// source of truth for the enum, used by the flag and by validation errors.
var ContextValues = []Context{ContextHTML, ContextJS, ContextAttribute, ContextURI}

// ParseContext validates a raw --context value against ContextValues.
// An empty string is treated as the default (html). An unknown value
// produces an error that lists every supported value instead of being
// silently coerced back to a default.
func ParseContext(raw string) (Context, error) {
	candidate := Context(strings.ToLower(strings.TrimSpace(raw)))
	if candidate == "" {
		return ContextHTML, nil
	}
	for _, valid := range ContextValues {
		if candidate == valid {
			return candidate, nil
		}
	}

	names := make([]string, 0, len(ContextValues))
	for _, valid := range ContextValues {
		names = append(names, string(valid))
	}
	return "", fmt.Errorf("invalid --context value %q: must be one of %s", raw, strings.Join(names, ", "))
}

type Arguments struct {
	Concurrency     int
	Header          string
	HeaderFile      string
	Payload         string
	PayloadFile     string
	Method          string
	AppendMode      bool
	Parameters      bool
	Debug           bool
	RateLimit       float64
	FollowRedirects bool
	Trace           bool
	Context         Context
}

// Flag variables
var (
	debug           bool
	concurrency     int
	payload         string
	payloadFile     string
	method          string
	header          string
	headerFile      string
	appendMode      bool
	parameters      bool
	rateLimit       float64
	followRedirects bool
	trace           bool
	contextRaw      string
)

// ValidateArgs validates the arguments passed to the program and prints the
func (a *Arguments) ValidateArgs() {
	// prints the default help and exits the program with status 1.

	// The banner
	fmt.Printf(colours.BannerColor, `
  ____                     
 | __ )  __  __  ___   ___ 
 |  _ \  \ \/ / / __| / __|
 | |_) |  >  <  \__ \ \__ \
 |____/  /_/\_\ |___/ |___/
                                        
	`, "")
	fmt.Printf(colours.TextColor, "", "v0.0.3")
	fmt.Printf("\n")

	// Check if at least one header and one payload option is provided
	if (a.Header == "" && a.HeaderFile == "") && (a.Payload == "" && a.PayloadFile == "") {
		flag.PrintDefaults()
		os.Exit(1)
	}
}

// NewArguments parses the command line flags and returns a pointer to an Arguments
// object. The Arguments object contains the parsed values of the flags, which can
// be used to configure the program. The function exits with an error message if
// there is an error parsing the flags, for example an unknown --context value.
func NewArguments() *Arguments {

	// Define the flags
	flag.IntVar(&concurrency, "c", 30, "Set the concurrency level for the scanner")
	flag.StringVar(&header, "H", "", "Set a single custom header to test for blind XSS")
	flag.StringVar(&headerFile, "hf", "", "Path to file containing headers to test for blind XSS")
	flag.StringVar(&payload, "p", "", "The blind XSS payload to test")
	flag.StringVar(&payloadFile, "pf", "", "Path to file containing payloads to test for blind XSS")
	flag.BoolVar(&appendMode, "a", false, "Append the payload to the parameter value when testing")
	flag.BoolVar(&parameters, "t", false, "Test the parameters for blind XSS by appending the payload to the parameter value")
	flag.StringVar(&method, "X", "", "The HTTP method to use when testing (GET, POST, etc.)")
	flag.BoolVar(&debug, "v", false, "Enable debug mode to view full request details and debug information")
	flag.Float64Var(&rateLimit, "rl", 0, "Rate limit in requests per second (optional to prevent abuse)")
	flag.BoolVar(&followRedirects, "f", false, "Follow redirects when testing (optional)")
	flag.BoolVar(&trace, "l", false, "Enable trace mode to track which host is vulnerable to XSS, if your canary server support custom parameters, insert url={LINK}")
	flag.StringVar(&contextRaw, "context", string(ContextHTML),
		"Injection context used to encode the callback, one of: html, js, attribute, uri (default html)")

	// Parse the arguments
	flag.Parse()

	// Enum validation: reject unknown values loudly instead of silently
	// falling back to the default context.
	contextValue, err := ParseContext(contextRaw)
	if err != nil {
		fmt.Printf(colours.ErrorColor, err.Error())
		os.Exit(2)
	}

	return &Arguments{
		Concurrency:     concurrency,
		Header:          header,
		HeaderFile:      headerFile,
		Payload:         payload,
		PayloadFile:     payloadFile,
		Method:          method,
		AppendMode:      appendMode,
		Parameters:      parameters,
		Debug:           debug,
		RateLimit:       rateLimit,
		FollowRedirects: followRedirects,
		Trace:           trace,
		Context:         contextValue,
	}
}
