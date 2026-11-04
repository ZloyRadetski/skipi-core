package skipicore

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startLoggingCore runs a real Core with a sniffing SOCKS inbound, a direct outbound, a blackhole for
// blocked.test and file logs, and returns the SOCKS port.
func startLoggingCore(t *testing.T, controller *CoreController, directory string, logLevel string) int {
	t.Helper()
	port := reserveLocalPort(t)
	config := fmt.Sprintf(`{
		"log": {"loglevel": %q, "access": %q, "error": %q},
		"inbounds": [{
			"tag": "socks-in", "listen": "127.0.0.1", "port": %d, "protocol": "socks",
			"settings": {"auth": "noauth", "udp": true},
			"sniffing": {"enabled": true, "destOverride": ["http", "tls"], "routeOnly": true}
		}],
		"outbounds": [
			{"tag": "direct", "protocol": "freedom"},
			{"tag": "block", "protocol": "blackhole"}
		],
		"routing": {"rules": [{"domain": ["domain:blocked.test"], "outboundTag": "block"}]}
	}`, logLevel, filepath.Join(directory, "access.log"), filepath.Join(directory, "error.log"), port)
	if err := controller.StartLoop(config, 0); err != nil {
		t.Fatalf("StartLoop: %v", err)
	}
	t.Cleanup(func() { _ = controller.StopLoop() })
	return port
}

// connectThroughSocks opens a no-auth SOCKS5 CONNECT to an IPv4 target.
func connectThroughSocks(t *testing.T, socksPort int, target *net.TCPAddr) net.Conn {
	t.Helper()
	var connection net.Conn
	var err error
	for attempt := 0; attempt < 100; attempt++ {
		connection, err = net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)))
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial SOCKS: %v", err)
	}
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connection.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("SOCKS greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(connection, reply); err != nil {
		t.Fatalf("SOCKS greeting reply: %v", err)
	}
	request := append([]byte{5, 1, 0, 1}, target.IP.To4()...)
	request = append(request, byte(target.Port>>8), byte(target.Port))
	if _, err := connection.Write(request); err != nil {
		t.Fatalf("SOCKS connect: %v", err)
	}
	response := make([]byte, 10)
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatalf("SOCKS connect reply: %v", err)
	}
	return connection
}

// requestHostThroughSocks sends a plain HTTP request by IP with [host] in its Host header, so only
// sniffing can learn the name, as with a TUN client.
func requestHostThroughSocks(t *testing.T, socksPort int, server *httptest.Server, host string) {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	target, err := net.ResolveTCPAddr("tcp", parsed.Host)
	if err != nil {
		t.Fatalf("resolve server: %v", err)
	}
	connection := connectThroughSocks(t, socksPort, target)
	defer connection.Close()
	if _, err := fmt.Fprintf(connection, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host); err != nil {
		t.Fatalf("send request: %v", err)
	}
	_, _ = bufio.NewReader(connection).ReadString('\n')
}

func newOkServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server
}

func waitForFileText(t *testing.T, path string, text string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if content, err := os.ReadFile(path); err == nil && strings.Contains(string(content), text) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	content, _ := os.ReadFile(path)
	t.Fatalf("%s never contained %q:\n%s", filepath.Base(path), text, content)
}

// An outbound probe builds a second Xray instance, and Xray's logger is process-global: the running
// session must keep writing its logs after the probe has come and gone.
func TestRunningCoreKeepsItsLogsAfterAnOutboundProbe(t *testing.T) {
	directory := t.TempDir()
	controller := NewCoreController(&dummyCallbackHandler{})
	socksPort := startLoggingCore(t, controller, directory, "warning")
	accessLog := filepath.Join(directory, "access.log")

	first := newOkServer(t)
	requestHostThroughSocks(t, socksPort, first, "before.test")
	waitForFileText(t, accessLog, strings.TrimPrefix(first.URL, "http://"))

	probeTarget := newOkServer(t)
	probeConfig := fmt.Sprintf(`{
		"log": {"loglevel": "warning", "access": %q, "error": %q},
		"outbounds": [{"tag": "direct", "protocol": "freedom"}]
	}`, filepath.Join(directory, "access.log"), filepath.Join(directory, "error.log"))
	if _, err := MeasureOutboundDelay(probeConfig, probeTarget.URL); err != nil {
		t.Fatalf("MeasureOutboundDelay: %v", err)
	}

	second := newOkServer(t)
	requestHostThroughSocks(t, socksPort, second, "after.test")
	waitForFileText(t, accessLog, strings.TrimPrefix(second.URL, "http://"))
}
