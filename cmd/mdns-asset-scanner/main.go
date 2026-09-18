package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	mdns "github.com/hezhihaolala/hsxa-security-platform/internal/mdns"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("mdns-asset-scanner", flag.ContinueOnError)
	flags.SetOutput(stderr)
	cidr := flags.String("cidr", "", "authorized IPv4 CIDR to probe (required)")
	portValue := flags.String("ports", "1-65535", "SRV ports to include, e.g. 80,443,5000-5010")
	timeout := flags.Duration("timeout", 3*time.Second, "overall discovery timeout")
	concurrency := flags.Int("concurrency", 64, "maximum concurrent UDP send workers (1-1024)")
	jsonOutput := flags.Bool("json", false, "emit JSON instead of text")
	verbose := flags.Bool("verbose", false, "write diagnostic messages to stderr")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *cidr == "" {
		return fmt.Errorf("--cidr is required")
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}

	ports, err := mdns.ParsePorts(*portValue)
	if err != nil {
		return fmt.Errorf("parse --ports: %w", err)
	}
	scanner, err := mdns.NewScanner(mdns.Config{
		CIDR:        *cidr,
		Ports:       ports,
		Timeout:     *timeout,
		Concurrency: *concurrency,
		Verbose:     *verbose,
		LogWriter:   stderr,
	})
	if err != nil {
		return err
	}

	assets, err := scanner.Discover(ctx)
	if err != nil {
		return fmt.Errorf("discover assets: %w", err)
	}
	if *jsonOutput {
		return mdns.WriteJSON(stdout, assets)
	}
	return mdns.WriteText(stdout, assets)
}
