package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ANSI colors
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBold   = "\033[1m"
)

type result struct {
	subdomain string
	certCN    string
	sans      []string
	err       string
	mismatch  bool
}

func check(subdomain string, timeout time.Duration) result {
	host, ok := hostFromInput(subdomain)
	if !ok {
		return result{subdomain: subdomain, err: "could not parse host"}
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, "443"), &tls.Config{
		InsecureSkipVerify: true, // inspect even invalid/expired certs
		ServerName:         host,
	})
	if err != nil {
		return result{subdomain: subdomain, err: err.Error()}
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return result{subdomain: subdomain, err: "no certificates presented"}
	}

	leaf := certs[0]
	cn := leaf.Subject.CommonName
	sans := leaf.DNSNames
	mismatch := !certCoversHost(host, cn, sans)

	return result{
		subdomain: subdomain,
		certCN:    cn,
		sans:      sans,
		mismatch:  mismatch,
	}
}

// hostFromInput reduces an input line to a bare hostname. It accepts a plain
// host, host:port, or a full URL, so output from tools that emit URLs still
// works. Returns false for anything with no usable host.
func hostFromInput(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}
	if strings.Contains(line, "://") {
		u, err := url.Parse(line)
		if err != nil || u.Hostname() == "" {
			return "", false
		}
		return u.Hostname(), true
	}
	if h, _, err := net.SplitHostPort(line); err == nil && h != "" {
		return h, true
	}
	return line, true
}

// certCoversHost reports whether the given CN or SANs cover the host.
//
// For exact names and single-level wildcards (*.example.com covering
// foo.example.com) we apply strict RFC 6125 matching.
//
// For takeover detection we also apply a looser check: if a wildcard's base
// domain is a suffix of the queried host (e.g. *.yahoo.com covering
// download.360.yahoo.com), the cert clearly belongs to the same organisation
// and is not a hostile takeover — just a deep subdomain the cert doesn't
// strictly cover.
func certCoversHost(host, cn string, sans []string) bool {
	host = strings.ToLower(host)
	for _, name := range append([]string{cn}, sans...) {
		name = strings.ToLower(name)
		// Exact match
		if name == host {
			return true
		}
		if strings.HasPrefix(name, "*.") {
			// Match any subdomain depth under the wildcard base.
			// e.g. *.yahoo.com covers foo.yahoo.com AND download.360.yahoo.com.
			// This avoids false positives where the cert belongs to the same org
			// but doesn't strictly cover a deep subdomain per RFC 6125.
			base := name[2:] // "yahoo.com" from "*.yahoo.com"
			if strings.HasSuffix(host, "."+base) {
				return true
			}
		}
	}
	return false
}

func printResult(r result, verbose bool) {
	switch {
	case r.err != "":
		if verbose {
			fmt.Printf("%s[ERROR]%s    %-40s %s\n", colorYellow, colorReset, r.subdomain, r.err)
		}

	case r.mismatch:
		extra := ""
		if len(r.sans) > 0 {
			extra = fmt.Sprintf("  SANs: %s", strings.Join(r.sans, ", "))
		}
		fmt.Printf("%s%s[MISMATCH]%s %-40s cert CN=%s%s\n",
			colorBold, colorRed, colorReset, r.subdomain, r.certCN, extra)

	default:
		if verbose {
			fmt.Printf("%s[OK]%s       %-40s cert CN=%s\n", colorGreen, colorReset, r.subdomain, r.certCN)
		}
	}
}

func main() {
	verbose := flag.Bool("v", false, "verbose: show all results, not just mismatches")
	workers := flag.Int("c", 20, "number of concurrent workers")
	timeout := flag.Duration("t", 5*time.Second, "TLS dial timeout")
	flag.Parse()

	if *workers < 1 {
		fmt.Fprintf(os.Stderr, "-c must be at least 1 (got %d)\n", *workers)
		os.Exit(2)
	}

	var subdomains []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		subdomains = append(subdomains, line)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "stdin error: %v\n", err)
		os.Exit(1)
	}
	if len(subdomains) == 0 {
		fmt.Fprintln(os.Stderr, "No subdomains provided on stdin.")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Checking %d subdomain(s) with concurrency=%d...\n\n", len(subdomains), *workers)

	jobs := make(chan string, *workers)
	results := make(chan result, len(subdomains))

	var wg sync.WaitGroup
	for range *workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sub := range jobs {
				results <- check(sub, *timeout)
			}
		}()
	}

	go func() {
		for _, sub := range subdomains {
			jobs <- sub
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var mismatches int
	for r := range results {
		printResult(r, *verbose)
		if r.mismatch {
			mismatches++
		}
	}

	fmt.Fprintf(os.Stderr, "\nDone. %d mismatch(es) found out of %d subdomains.\n", mismatches, len(subdomains))
}
