package main

import "testing"

func TestHostFromInput(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"example.com", "example.com", true},
		{"  example.com  ", "example.com", true},
		{"example.com:8443", "example.com", true},
		{"https://example.com/path?x=1", "example.com", true},
		{"http://user:pw@example.com:443/", "example.com", true},
		{"", "", false},
		{"https://", "", false},
	}
	for _, c := range cases {
		got, ok := hostFromInput(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("hostFromInput(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestCertCoversHost(t *testing.T) {
	cases := []struct {
		name string
		host string
		cn   string
		sans []string
		want bool
	}{
		{"exact CN", "app.example.com", "app.example.com", nil, true},
		{"exact SAN", "app.example.com", "other", []string{"app.example.com"}, true},
		{"wildcard one level", "foo.example.com", "*.example.com", nil, true},
		{"wildcard deep subdomain same org", "download.360.yahoo.com", "*.yahoo.com", nil, true},
		{"case insensitive", "APP.example.com", "app.EXAMPLE.com", nil, true},
		{"clear mismatch", "app.example.com", "attacker.io", []string{"attacker.io"}, false},
		{"wildcard base not a suffix", "app.example.com", "*.other.com", nil, false},
	}
	for _, c := range cases {
		if got := certCoversHost(c.host, c.cn, c.sans); got != c.want {
			t.Errorf("%s: certCoversHost(%q,%q,%v) = %v, want %v", c.name, c.host, c.cn, c.sans, got, c.want)
		}
	}
}
