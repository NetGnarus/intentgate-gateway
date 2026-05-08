// Command igctl is a small developer CLI for IntentGate.
//
// Three subcommands:
//
//	igctl gen-key            print a fresh base64url HMAC master key
//	igctl mint [flags]       mint a capability token (prints encoded token)
//	igctl decode <token>     pretty-print a token without verifying it
//
// The CLI is for development and one-off operator tasks. It deliberately
// has no dependencies on the gateway runtime — it only imports the
// capability package, so it can be vendored into customer environments
// to mint tokens against their own master key.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/NetGnarus/intentgate-gateway/internal/capability"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "gen-key":
		cmdGenKey()
	case "mint":
		cmdMint(os.Args[2:])
	case "decode":
		cmdDecode(os.Args[2:])
	case "-h", "--help", "help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprintln(w, `igctl - IntentGate developer CLI

Usage:
  igctl gen-key                          print a fresh base64url master key
  igctl mint [flags]                     mint a capability token
  igctl decode <encoded-token>           pretty-print a token (no verify)

Run 'igctl mint -h' for the mint flags.

The master key for 'mint' is read from --master-key or the
INTENTGATE_MASTER_KEY environment variable.`)
}

// cmdGenKey writes a fresh base64url-encoded 32-byte master key to stdout.
func cmdGenKey() {
	key, err := capability.NewMasterKey()
	if err != nil {
		die(err)
	}
	fmt.Println(base64.RawURLEncoding.EncodeToString(key))
}

// cmdMint mints a capability token from CLI flags and prints it
// base64url-encoded for use in an Authorization: Bearer header.
func cmdMint(args []string) {
	fs := flag.NewFlagSet("mint", flag.ExitOnError)
	masterKeyB64 := fs.String("master-key", os.Getenv("INTENTGATE_MASTER_KEY"),
		"base64url master key (defaults to $INTENTGATE_MASTER_KEY)")
	subject := fs.String("subject", "",
		"agent ID this token will be bound to (required)")
	tools := fs.String("tools", "",
		"comma-separated tool whitelist (e.g. read_invoice,record_in_ledger)")
	forbidden := fs.String("forbidden", "",
		"comma-separated tool blacklist")
	ttl := fs.Duration("ttl", 0,
		"time-to-live (e.g. 1h, 30m). 0 = no expiry caveat")
	issuer := fs.String("issuer", "",
		"issuer name (default: intentgate)")
	pretty := fs.Bool("pretty", false,
		"also print the decoded token to stderr for inspection")
	if err := fs.Parse(args); err != nil {
		die(err)
	}
	if *subject == "" {
		fs.Usage()
		die(fmt.Errorf("--subject is required"))
	}
	key, err := capability.MasterKeyFromBase64(*masterKeyB64)
	if err != nil {
		die(fmt.Errorf("master key: %w", err))
	}

	var caveats []capability.Caveat
	if *tools != "" {
		caveats = append(caveats, capability.Caveat{
			Type:  capability.CaveatToolWhitelist,
			Tools: splitCSV(*tools),
		})
	}
	if *forbidden != "" {
		caveats = append(caveats, capability.Caveat{
			Type:  capability.CaveatToolBlacklist,
			Tools: splitCSV(*forbidden),
		})
	}

	opts := capability.MintOptions{
		Issuer:  *issuer,
		Subject: *subject,
		Caveats: caveats,
	}
	if *ttl > 0 {
		opts.Expiry = time.Now().Add(*ttl)
	}

	tok, err := capability.Mint(key, opts)
	if err != nil {
		die(err)
	}
	encoded, err := tok.Encode()
	if err != nil {
		die(err)
	}

	if *pretty {
		out, _ := json.MarshalIndent(tok, "", "  ")
		fmt.Fprintln(os.Stderr, string(out))
	}
	fmt.Println(encoded)
}

// cmdDecode prints a token's decoded JSON without verifying its signature.
// Useful for inspecting a token in flight; do NOT trust the output to
// authorize anything.
func cmdDecode(args []string) {
	if len(args) < 1 {
		die(fmt.Errorf("usage: igctl decode <encoded-token>"))
	}
	tok, err := capability.Decode(args[0])
	if err != nil {
		die(err)
	}
	out, err := json.MarshalIndent(tok, "", "  ")
	if err != nil {
		die(err)
	}
	fmt.Println(string(out))
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
