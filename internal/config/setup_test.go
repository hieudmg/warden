package config

import "testing"

func TestSetupHTTPSAndProxyConfiguration(t *testing.T) {
	good := Setup{PublicOrigin: "https://warden.example:8443", RPID: "warden.example", Mode: "proxy", BackendAuthority: "127.0.0.1:8080"}
	if err := good.Validate("127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Setup, *string){
		func(s *Setup, _ *string) { s.PublicOrigin = "http://warden.example" },
		func(s *Setup, _ *string) { s.PublicOrigin = "https://warden.example/" },
		func(s *Setup, _ *string) { s.PublicOrigin = "https://user@warden.example" },
		func(s *Setup, _ *string) { s.PublicOrigin = "https://warden.example:443" },
		func(s *Setup, _ *string) { s.PublicOrigin = "https://warden.example:08443" },
		func(s *Setup, _ *string) { s.PublicOrigin = "https://warden.example:" },
		func(s *Setup, _ *string) { s.RPID = "attacker.example" },
		func(_ *Setup, b *string) { *b = "0.0.0.0:8080" },
		func(_ *Setup, b *string) { *b = "localhost:8080" },
		func(s *Setup, _ *string) { s.BackendAuthority = "attacker:8080" },
		func(s *Setup, _ *string) { s.Mode = "tls" },
	} {
		s := good
		b := "127.0.0.1:8080"
		mutate(&s, &b)
		if s.Validate(b) == nil {
			t.Fatalf("accepted %+v bind %s", s, b)
		}
	}
}
