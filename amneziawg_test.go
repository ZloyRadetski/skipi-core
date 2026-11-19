package skipicore

import (
	"fmt"
	"github.com/ZloyRadetski/skipi-core/internal/amneziawg"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

func TestAmneziaWgConfigAndIpc(t *testing.T) {
	awgJSON := `{
		"protocol": "wireguard",
		"settings": {
			"secretKey": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE=",
			"address": ["10.8.0.2/32"],
			"dnsServers": ["9.9.9.9"],
			"peers": [
				{
					"publicKey": "YW5vdGhlciB2YWxpZCBrZXkgZm9yIHRlc3Rpbmcgb2s=",
					"endpoint": "192.0.2.1:51820",
					"allowedIPs": ["0.0.0.0/0"],
					"keepAlive": 25
				}
			],
			"mtu": 1420,
			"jc": 5,
			"jmin": 30,
			"jmax": 80,
			"s1": 20,
			"s2": 40,
			"s3": 60,
			"s4": 80,
			"h1": 11111,
			"h2": 22222,
			"h3": 33333,
			"h4": 44444
		}
	}`

	settings, err := ParseAmneziaWgSettings(awgJSON)
	if err != nil {
		t.Fatalf("ParseAmneziaWgSettings failed: %v", err)
	}
	if !settings.HasAmneziaParams() {
		t.Fatal("expected HasAmneziaParams to be true")
	}
	if settings.Jc != 5 || settings.Jmin != 30 || settings.Jmax != 80 {
		t.Fatalf("unexpected Jc/Jmin/Jmax: %d/%d/%d", settings.Jc, settings.Jmin, settings.Jmax)
	}
	if settings.S1 != 20 || settings.S2 != 40 || settings.S3 != 60 || settings.S4 != 80 {
		t.Fatalf("unexpected S1/S2/S3/S4: %d/%d/%d/%d", settings.S1, settings.S2, settings.S3, settings.S4)
	}
	if len(settings.DNSServers) != 1 || settings.DNSServers[0] != "9.9.9.9" {
		t.Fatalf("unexpected DNS servers: %#v", settings.DNSServers)
	}

	ipc, err := settings.BuildIpcConfig()
	if err != nil {
		t.Fatalf("BuildIpcConfig failed: %v", err)
	}
	if !strings.Contains(ipc, "jc=5") {
		t.Errorf("ipc missing jc=5: %s", ipc)
	}
	if !strings.Contains(ipc, "jmin=30") {
		t.Errorf("ipc missing jmin=30: %s", ipc)
	}
	if !strings.Contains(ipc, "jmax=80") {
		t.Errorf("ipc missing jmax=80: %s", ipc)
	}
	if !strings.Contains(ipc, "s1=20") {
		t.Errorf("ipc missing s1=20: %s", ipc)
	}
	if !strings.Contains(ipc, "s2=40") {
		t.Errorf("ipc missing s2=40: %s", ipc)
	}
	if !strings.Contains(ipc, "s3=60") || !strings.Contains(ipc, "s4=80") {
		t.Errorf("ipc missing s3/s4: %s", ipc)
	}
	if !strings.Contains(ipc, "h1=11111") {
		t.Errorf("ipc missing h1=11111: %s", ipc)
	}

	fullConfig := fmt.Sprintf(`{
		"outbounds": [
			%s
		]
	}`, awgJSON)
	rewritten := RewriteWireguardOutboundToSocks(fullConfig, 10809)
	if !strings.Contains(rewritten, `"protocol":"socks"`) {
		t.Fatalf("expected rewritten config to contain protocol socks, got: %s", rewritten)
	}
	if !strings.Contains(rewritten, `10809`) {
		t.Fatalf("expected rewritten config to contain port 10809, got: %s", rewritten)
	}
}

func TestAmneziaWgRunnerLifecycle(t *testing.T) {
	protector := &dummySocketProtector{}
	SetAmneziaWgSocketProtector(protector)
	defer SetAmneziaWgSocketProtector(nil)

	awgJSON := `{
		"secretKey": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE=",
		"address": ["10.8.0.2/32"],
		"dnsServers": ["1.1.1.1"],
		"peers": [
			{
				"publicKey": "YW5vdGhlciB2YWxpZCBrZXkgZm9yIHRlc3Rpbmcgb2s=",
				"endpoint": "127.0.0.1:59999",
				"allowedIPs": ["0.0.0.0/0"]
			}
		],
		"jc": 3,
		"jmin": 40,
		"jmax": 70,
		"s1": 15,
		"s2": 25,
		"h1": "12345"
	}`

	settings, err := ParseAmneziaWgSettings(awgJSON)
	if err != nil {
		t.Fatalf("ParseAmneziaWgSettings failed: %v", err)
	}

	runner, err := NewAmneziaWgRunner(settings, 0)
	if err != nil {
		t.Fatalf("NewAmneziaWgRunner failed: %v", err)
	}
	runner.socksPort = 0 // ephemeral: the default 10809 may be held by a running SKIPI

	if err := runner.Start(); err != nil {
		t.Fatalf("runner.Start failed: %v", err)
	}
	if runner.socksPort <= 0 {
		t.Fatalf("expected positive socks port, got %d", runner.socksPort)
	}
	if protector.protectedCount == 0 {
		t.Fatal("expected AmneziaWG peer sockets to be passed through the protector")
	}

	// SOCKS5 handshake test to verify listener is functioning
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", runner.socksPort))
	if err != nil {
		t.Fatalf("failed to dial socks listener: %v", err)
	}
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	var reply [2]byte
	_, _ = io.ReadFull(conn, reply[:])
	conn.Close()
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("unexpected socks handshake reply: %v", reply)
	}

	if err := runner.Stop(); err != nil {
		t.Fatalf("runner.Stop failed: %v", err)
	}
}

func TestAmneziaWgRequiresExplicitDNS(t *testing.T) {
	_, err := (&AmneziaWgSettings{}).netstackDNSAddresses()
	if err == nil || !strings.Contains(err.Error(), "dnsServers is required") {
		t.Fatalf("expected missing DNS error, got %v", err)
	}

	_, err = (&AmneziaWgSettings{DNSServers: []string{"https://dns.example/dns-query"}}).netstackDNSAddresses()
	if err == nil || !strings.Contains(err.Error(), "invalid AmneziaWG DNS server") {
		t.Fatalf("expected raw-IP DNS validation error, got %v", err)
	}
}

func TestAmneziaWgSupportsHeaderRangesAndObfuscationChains(t *testing.T) {
	settings := &AmneziaWgSettings{
		SecretKey:  "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE=",
		DNSServers: []string{"9.9.9.9"},
		Jc:         9,
		Jmin:       30,
		Jmax:       90,
		S1:         110,
		S2:         120,
		S3:         47,
		S4:         23,
		H1:         "7291435-486117520",
		H2:         "602843917-1157629843",
		H3:         "1249871566-1680354947",
		H4:         "1781926002-2106438100",
		I1:         "<b 0x0003><r 2><b 0x2112A442><r 12><r 20>",
		I2:         "<b 0x0103><r 2><b 0x2112A442><r 12><r 24>",
		I3:         "<b 0x0008><r 2><b 0x2112A442><r 12><r 16>",
		Peers: []*AmneziaWgPeer{{
			PublicKey:  "YW5vdGhlciB2YWxpZCBrZXkgZm9yIHRlc3Rpbmcgb2s=",
			Endpoint:   "198.51.100.2:50125",
			AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		}},
	}

	if err := settings.validateNativeRunnerCompatibility(); err != nil {
		t.Fatalf("valid AmneziaWG ranges/chains were rejected: %v", err)
	}
	if !settings.HasAmneziaParams() {
		t.Fatal("expected I/H settings to count as AmneziaWG parameters")
	}
	ipc, err := settings.BuildIpcConfig()
	if err != nil {
		t.Fatalf("BuildIpcConfig failed: %v", err)
	}
	for _, expected := range []string{
		"h1=7291435-486117520",
		"h4=1781926002-2106438100",
		"i1=<b 0x0003><r 2><b 0x2112A442><r 12><r 20>",
		"i3=<b 0x0008><r 2><b 0x2112A442><r 12><r 16>",
	} {
		if !strings.Contains(ipc, expected) {
			t.Errorf("IPC config is missing %q: %s", expected, ipc)
		}
	}
}

func TestAmneziaWgRejectsUnsafeJunkCountBeforeRunnerStartup(t *testing.T) {
	settings := &AmneziaWgSettings{
		Jc: 129,
		Peers: []*AmneziaWgPeer{{
			Endpoint: "198.51.100.2:51820",
		}},
	}

	err := settings.validateNativeRunnerCompatibility()
	if err == nil || !strings.Contains(err.Error(), "jc") {
		t.Fatalf("expected unsafe jc to be rejected, got %v", err)
	}
}

func TestAmneziaWg3SettingsReachTheRunnerIpcConfig(t *testing.T) {
	const headerKey = "c29tZSBoZWFkZXIgcHJvdGVjdGlvbiBrZXkgb2shISE="
	settings, err := ParseAmneziaWgSettings(`{
		"protocol": "wireguard",
		"settings": {
			"secretKey": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE=",
			"address": ["10.8.0.2/32"],
			"peers": [{
				"publicKey": "YW5vdGhlciB2YWxpZCBrZXkgZm9yIHRlc3Rpbmcgb2s=",
		"endpoint": "192.0.2.1:51820",
				"keepAlive": "20-30"
			}],
			"headerProtectionKey": "` + headerKey + `",
			"s1": 12, "s2": 20, "s3": 30, "s4": 40,
			"contentPaddingAddition": "16-64",
			"rekeyAfterTime": 120,
			"rekeyTimeout": "5-10",
			"rejectAfterTime": 180,
			"keepaliveTimeout": 10,
			"maxHandshakeAttempts": "20-90"
		}
	}`)
	if err != nil {
		t.Fatalf("ParseAmneziaWgSettings failed: %v", err)
	}
	if !settings.HasAmneziaParams() {
		t.Fatal("AmneziaWG 3.0 settings alone must count as AmneziaWG parameters")
	}
	if err := settings.validateNativeRunnerCompatibility(); err != nil {
		t.Fatalf("valid AmneziaWG 3.0 settings were rejected: %v", err)
	}
	ipc, err := settings.BuildIpcConfig()
	if err != nil {
		t.Fatalf("BuildIpcConfig failed: %v", err)
	}
	headerHex, err := amneziawg.DecodeKeyToHex(headerKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"header_protection_key=" + headerHex + "\n",
		"content_padding_addition=16-64\n",
		"rekey_after_time=120\n",
		"rekey_timeout=5-10\n",
		"reject_after_time=180\n",
		"keepalive_timeout=10\n",
		"max_handshake_attempts=20-90\n",
		"persistent_keepalive_interval=20-30\n",
	} {
		if !strings.Contains(ipc, expected) {
			t.Errorf("IPC config is missing %q: %s", expected, ipc)
		}
	}
}

func TestAmneziaWg3UnsetSettingsAddNothingToTheIpcConfig(t *testing.T) {
	settings := &AmneziaWgSettings{
		SecretKey: "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE=",
		Jc:        4,
		Peers: []*AmneziaWgPeer{{
			PublicKey: "YW5vdGhlciB2YWxpZCBrZXkgZm9yIHRlc3Rpbmcgb2s=",
			Endpoint:  "192.0.2.1:51820",
		}},
	}
	ipc, err := settings.BuildIpcConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"header_protection_key", "content_padding", "rekey_", "reject_after", "keepalive_timeout", "max_handshake", "persistent_keepalive"} {
		if strings.Contains(ipc, key) {
			t.Errorf("unset AmneziaWG 3.0 setting %q leaked into the IPC config: %s", key, ipc)
		}
	}
}

func TestAmneziaWg3RejectsInvalidRangesAndKeyBeforeRunnerStartup(t *testing.T) {
	peers := []*AmneziaWgPeer{{Endpoint: "198.51.100.2:51820"}}
	cases := map[string]*AmneziaWgSettings{
		"ContentPaddingAddition": {ContentPaddingAddition: "9-3", Peers: peers},
		"RekeyAfterTime":         {RekeyAfterTime: "65536", Peers: peers},
		"RekeyTimeout":           {RekeyTimeout: "abc", Peers: peers},
		"RejectAfterTime":        {RejectAfterTime: "1-2-3", Peers: peers},
		"KeepaliveTimeout":       {KeepaliveTimeout: "-1", Peers: peers},
		"MaxHandshakeAttempts":   {MaxHandshakeAttempts: "5-", Peers: peers},
		"HeaderProtectionKey":    {HeaderProtectionKey: "not-a-key", Peers: peers},
		"PersistentKeepalive":    {Peers: []*AmneziaWgPeer{{Endpoint: "198.51.100.2:51820", KeepAlive: "7-1"}}},
	}
	for name, settings := range cases {
		err := settings.validateNativeRunnerCompatibility()
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: expected a rejection naming the field, got %v", name, err)
		}
	}
}

// The real AmneziaWG runner, not just the string builder, must accept the 3.0 IPC config.
func TestAmneziaWg3IpcConfigIsAcceptedByTheRealRunner(t *testing.T) {
	settings := &AmneziaWgSettings{
		SecretKey:              "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE=",
		HeaderProtectionKey:    "c29tZSBoZWFkZXIgcHJvdGVjdGlvbiBrZXkgb2shISE=",
		ContentPaddingAddition: "16-64",
		RekeyAfterTime:         120,
		RekeyTimeout:           "5-10",
		RejectAfterTime:        180,
		KeepaliveTimeout:       10,
		MaxHandshakeAttempts:   "20-90",
		Jc:                     4,
		S1:                     12,
		S2:                     20,
		S3:                     30,
		S4:                     40,
		Peers: []*AmneziaWgPeer{{
			PublicKey: "YW5vdGhlciB2YWxpZCBrZXkgZm9yIHRlc3Rpbmcgb2s=",
			Endpoint:  "192.0.2.1:51820",
			KeepAlive: "20-30",
		}},
	}
	ipc, err := settings.BuildIpcConfig()
	if err != nil {
		t.Fatal(err)
	}
	tunDev, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.8.0.2")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), &device.Logger{
		Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {},
	})
	defer dev.Close()
	if err := dev.IpcSet(ipc); err != nil {
		t.Fatalf("the runner rejected the AmneziaWG 3.0 config: %v\n%s", err, ipc)
	}
	got, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"content_padding_addition=16-64", "rekey_after_time=120", "rekey_timeout=5-10",
		"reject_after_time=180", "keepalive_timeout=10", "max_handshake_attempts=20-90",
		"persistent_keepalive_interval=20-30",
	} {
		if !strings.Contains(got, expected) {
			t.Errorf("the runner did not keep %q: %s", expected, got)
		}
	}
}

// The runner refuses a header protection key unless S1..S4 each leave room for the 12-byte nonce.
func TestHeaderProtectionKeyNeedsEveryPaddingOfAtLeast12(t *testing.T) {
	const headerKey = "c29tZSBoZWFkZXIgcHJvdGVjdGlvbiBrZXkgb2shISE="
	peers := []*AmneziaWgPeer{{Endpoint: "198.51.100.2:51820"}}
	full := func() *AmneziaWgSettings {
		return &AmneziaWgSettings{HeaderProtectionKey: headerKey, S1: 12, S2: 12, S3: 12, S4: 12, Peers: peers}
	}
	if err := full().validateNativeRunnerCompatibility(); err != nil {
		t.Fatalf("paddings of exactly 12 must be accepted: %v", err)
	}
	for name, mutate := range map[string]func(*AmneziaWgSettings){
		"s1": func(s *AmneziaWgSettings) { s.S1 = 11 },
		"s2": func(s *AmneziaWgSettings) { s.S2 = 0 },
		"s3": func(s *AmneziaWgSettings) { s.S3 = 0 },
		"s4": func(s *AmneziaWgSettings) { s.S4 = 5 },
	} {
		settings := full()
		mutate(settings)
		err := settings.validateNativeRunnerCompatibility()
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s below 12 must be rejected naming the field, got %v", name, err)
		}
	}
	// Without the key small paddings stay valid.
	if err := (&AmneziaWgSettings{S1: 1, Peers: peers}).validateNativeRunnerCompatibility(); err != nil {
		t.Fatalf("small paddings without a header key must stay valid: %v", err)
	}
}

func TestAmneziaWg31FlagsReachTheRunnerIpcConfig(t *testing.T) {
	for name, tc := range map[string]struct {
		json string
		want []string
	}{
		"both on":          {`"randomTrailers": true, "disableCookies": true`, []string{"random_trailers=true\n", "disable_cookies=true\n"}},
		"explicit off":     {`"randomTrailers": false, "disableCookies": false`, []string{"random_trailers=false\n", "disable_cookies=false\n"}},
		"strings and nums": {`"randomTrailers": "on", "disableCookies": 1`, []string{"random_trailers=true\n", "disable_cookies=true\n"}},
		"off spellings":    {`"randomTrailers": "OFF", "disableCookies": "0"`, []string{"random_trailers=false\n", "disable_cookies=false\n"}},
	} {
		settings, err := ParseAmneziaWgSettings(`{"protocol":"wireguard","settings":{
			"secretKey": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE=",
			"peers": [{"publicKey": "YW5vdGhlciB2YWxpZCBrZXkgZm9yIHRlc3Rpbmcgb2s=", "endpoint": "192.0.2.1:51820"}],
			` + tc.json + `}}`)
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		if !settings.HasAmneziaParams() {
			t.Errorf("%s: a 3.1 flag alone must count as an AmneziaWG parameter", name)
		}
		if err := settings.validateNativeRunnerCompatibility(); err != nil {
			t.Fatalf("%s: rejected: %v", name, err)
		}
		ipc, err := settings.BuildIpcConfig()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, want := range tc.want {
			if !strings.Contains(ipc, want) {
				t.Errorf("%s: IPC config is missing %q: %s", name, want, ipc)
			}
		}
	}
}

func TestAmneziaWg31UnsetFlagsAddNothingAndBadOnesAreRejected(t *testing.T) {
	peers := []*AmneziaWgPeer{{Endpoint: "198.51.100.2:51820", PublicKey: "YW5vdGhlciB2YWxpZCBrZXkgZm9yIHRlc3Rpbmcgb2s="}}
	plain := &AmneziaWgSettings{SecretKey: "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE=", Jc: 4, Peers: peers}
	ipc, err := plain.BuildIpcConfig()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ipc, "random_trailers") || strings.Contains(ipc, "disable_cookies") {
		t.Errorf("unset 3.1 flags leaked into the IPC config: %s", ipc)
	}
	for name, settings := range map[string]*AmneziaWgSettings{
		"RandomTrailers": {RandomTrailers: "sometimes", Peers: peers},
		"DisableCookies": {DisableCookies: 2, Peers: peers},
	} {
		err := settings.validateNativeRunnerCompatibility()
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: expected a rejection naming the field, got %v", name, err)
		}
	}
}

// The real runner must accept what the builder emits for the 3.1 flags.
func TestAmneziaWg31FlagsAreAcceptedByTheRealRunner(t *testing.T) {
	settings := &AmneziaWgSettings{
		SecretKey:      "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZhbGlkIGtleSE=",
		Jc:             4,
		RandomTrailers: true,
		DisableCookies: "on",
		Peers: []*AmneziaWgPeer{{
			PublicKey: "YW5vdGhlciB2YWxpZCBrZXkgZm9yIHRlc3Rpbmcgb2s=",
			Endpoint:  "192.0.2.1:51820",
		}},
	}
	ipc, err := settings.BuildIpcConfig()
	if err != nil {
		t.Fatal(err)
	}
	tunDev, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.8.0.2")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), &device.Logger{
		Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {},
	})
	defer dev.Close()
	if err := dev.IpcSet(ipc); err != nil {
		t.Fatalf("the runner rejected the AmneziaWG 3.1 config: %v\n%s", err, ipc)
	}
	got, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	// IpcGet prints booleans as 1/0.
	for _, want := range []string{"random_trailers=1", "disable_cookies=1"} {
		if !strings.Contains(got, want) {
			t.Errorf("the runner did not keep %q: %s", want, got)
		}
	}
}
