# ipdanglr

A fast, concurrent Go tool to detect potential subdomain takeovers by comparing TLS certificate subjects against the queried hostname.

If a subdomain's certificate was issued for a completely different domain, it's a strong signal of a hostile takeover or dangling DNS record.

```
[MISMATCH] app.example.com                          cert CN=attacker.io  SANs: attacker.io
```

## How it works

For each subdomain, `ipdanglr` connects to port 443, retrieves the TLS certificate (including invalid or expired certs), and checks whether the certificate's CN or SANs actually cover that subdomain. Mismatches are flagged.

This is the equivalent of:

```bash
openssl s_client -connect sub.domain.com:443 </dev/null 2>/dev/null | grep subject
```

...but concurrent, colourised, and built for piping into recon workflows.

## Install

```bash
go install github.com/cybercdh/ipdanglr@latest
```

Or build from source:

```bash
git clone https://github.com/cybercdh/ipdanglr
cd ipdanglr
go build -o ipdanglr .
```

## Usage

```bash
cat subdomains.txt | ipdanglr
```

```bash
# verbose: also show OK and ERROR results
cat subdomains.txt | ipdanglr -v
```

Subdomains are read one per line from stdin. Lines beginning with `#` are ignored.

## Output

| Tag | Meaning | Default | `-v` |
|---|---|---|---|
| `[MISMATCH]` | Cert CN/SANs don't cover the queried host | shown (red) | shown |
| `[OK]` | Cert covers the queried host | hidden | shown (green) |
| `[ERROR]` | Connection failed or no cert presented | hidden | shown (yellow) |

## Example

```bash
$ cat targets.txt | ipdanglr
Checking 4 subdomain(s) with concurrency=20...

[MISMATCH] old.example.com                          cert CN=someservice.io  SANs: someservice.io
[MISMATCH] staging.example.com                      cert CN=parkingpage.net

Done. 2 mismatch(es) found out of 4 subdomains.
```

## Integration

Works well with subdomain enumeration tools:

```bash
subfinder -d example.com -silent | ipdanglr
assetfinder example.com | ipdanglr
cat subdomains.txt | ipdanglr | tee mismatches.txt
```

## License

MIT
