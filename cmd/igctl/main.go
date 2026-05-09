// Command igctl is a small developer CLI for IntentGate.
//
// Subcommands:
//
//	igctl gen-key            print a fresh base64url HMAC master key
//	igctl mint [flags]       mint a capability token (prints encoded token)
//	igctl decode <token>     pretty-print a token without verifying it
//	igctl revoke [flags]     revoke a token by JTI against a running gateway
//
// The CLI is for development and one-off operator tasks. The
// gen-key/mint/decode commands have no runtime dependencies — they only
// import the capability package, so the binary can be vendored into a
// customer environment to mint tokens against their own master key.
// The revoke command speaks HTTP to a gateway's admin API.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
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
	case "revoke":
		cmdRevoke(os.Args[2:])
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
  igctl revoke [flags]                   revoke a token via the gateway admin API

Run 'igctl mint -h' or 'igctl revoke -h' for per-command flags.

The master key for 'mint' is read from --master-key or the
INTENTGATE_MASTER_KEY environment variable.

The admin token for 'revoke' is read from --admin-token or the
INTENTGATE_ADMIN_TOKEN environment variable.`)
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
	maxCalls := fs.Int("max-calls", 0,
		"maximum total tool-calls allowed for this token (0 = unlimited)")
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
	if *maxCalls > 0 {
		caveats = append(caveats, capability.Caveat{
			Type:     capability.CaveatMaxCalls,
			MaxCalls: *maxCalls,
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

// cmdRevoke posts to a running gateway's /v1/admin/revoke endpoint to
// invalidate a token by JTI. The gateway must have INTENTGATE_ADMIN_TOKEN
// set; the same value goes into --admin-token (or $INTENTGATE_ADMIN_TOKEN).
func cmdRevoke(args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	gatewayURL := fs.String("gateway", os.Getenv("INTENTGATE_GATEWAY_URL"),
		"gateway base URL (e.g. http://localhost:8080); default $INTENTGATE_GATEWAY_URL")
	adminToken := fs.String("admin-token", os.Getenv("INTENTGATE_ADMIN_TOKEN"),
		"admin shared secret (defaults to $INTENTGATE_ADMIN_TOKEN)")
	jti := fs.String("jti", "",
		"JTI of the token to revoke (required). Find it via 'igctl decode <token>'")
	reason := fs.String("reason", "",
		"operator-supplied context recorded in the audit log")
	if err := fs.Parse(args); err != nil {
		die(err)
	}

	if *gatewayURL == "" {
		die(fmt.Errorf("--gateway is required (or set $INTENTGATE_GATEWAY_URL)"))
	}
	if *adminToken == "" {
		die(fmt.Errorf("--admin-token is required (or set $INTENTGATE_ADMIN_TOKEN)"))
	}
	if *jti == "" {
		die(fmt.Errorf("--jti is required"))
	}

	body, err := json.Marshal(map[string]string{"jti": *jti, "reason": *reason})
	if err != nil {
		die(err)
	}

	endpoint := strings.TrimRight(*gatewayURL, "/") + "/v1/admin/revoke"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		die(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+*adminToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		die(fmt.Errorf("POST %s: %w", endpoint, err))
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		die(fmt.Errorf("gateway returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody))))
	}
	fmt.Println(string(respBody))
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
