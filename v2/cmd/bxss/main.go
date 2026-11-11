package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/ethicalhackingplayground/bxss/v2/pkg/arguments"
	"github.com/ethicalhackingplayground/bxss/v2/pkg/colours"
	"github.com/ethicalhackingplayground/bxss/v2/pkg/payloads"
	"golang.org/x/time/rate"
)

var (
	limiter *rate.Limiter
	args    *arguments.Arguments
)

func main() {

	// Create the arguments
	args = arguments.NewArguments()
	if args == nil {
		return
	}

	// Validate the arguments
	args.ValidateArgs()

	if args.RateLimit > 0 {
		limiter = rate.NewLimiter(rate.Limit(args.RateLimit), 1)
	}

	// Create the payload parser
	payloadParser := payloads.NewPayload(args)
	if payloadParser == nil {
		fmt.Printf(colours.ErrorColor, "Error creating payload parser: "+"Something went wrong")
		os.Exit(1)
	}

	var headers []string
	if args.HeaderFile != "" {
		var err error
		headers, err = payloadParser.ReadLinesFromFile()
		if err != nil {
			fmt.Printf(colours.ErrorColor, "Error reading header file: "+err.Error())
			return
		}
	} else if args.Header != "" {
		headers = []string{args.Header}
	}

	var rawCallbacks []string
	if args.PayloadFile != "" {
		var err error
		rawCallbacks, err = payloadParser.ReadLinesFromFile()
		if err != nil {
			fmt.Printf(colours.ErrorColor, "Error reading payload file: "+err.Error())
			return
		}
	} else if args.Payload != "" {
		rawCallbacks = []string{args.Payload}
	}

	// Encode every raw callback once for the selected injection context.
	// The default html context is the identity transform, so legacy
	// payloads reach the scanner byte-for-byte unchanged.
	payloadList, err := payloads.BuildAll(rawCallbacks, args.Context)
	if err != nil {
		fmt.Printf(colours.ErrorColor, "Error building payloads for context "+string(args.Context)+": "+err.Error())
		os.Exit(2)
	}
	fmt.Printf(colours.NoticeColor, "Injection Context: "+string(args.Context))

	fmt.Printf(colours.NoticeColor, "Please Be Patient for bxss"+"")

	// Create a channel to send work items to the worker pool
	workChan := make(chan string)

	// Create a worker pool
	var wg sync.WaitGroup
	for i := 0; i < args.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for link := range workChan {
				payloadParser.ProcessPayloadsAndHeaders(limiter, link, payloadList, headers)
			}
		}()
	}

	// Start sending the work items to the channel
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // Increase buffer size
		for scanner.Scan() {
			link := strings.TrimSpace(scanner.Text())
			if link == "" {
				continue // Skip empty lines
			}
			workChan <- link
		}
		if err := scanner.Err(); err != nil {
			fmt.Printf(colours.ErrorColor, "Error reading input: "+err.Error())
		}
		close(workChan)
	}()

	wg.Wait()
}
