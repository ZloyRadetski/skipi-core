package skipicore

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	corecommlog "github.com/xtls/xray-core/common/log"
)

type connectionLogEntryJSON struct {
	Seq      int64  `json:"seq"`
	Time     int64  `json:"time"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Network  string `json:"network"`
	Outbound string `json:"outbound"`
}

type connectionLogJSON struct {
	Seq     int64                    `json:"seq"`
	Entries []connectionLogEntryJSON `json:"entries"`
}

func readConnectionLog(t *testing.T, controller *CoreController, after int64) connectionLogJSON {
	t.Helper()
	var parsed connectionLogJSON
	if err := json.Unmarshal([]byte(controller.ReadConnectionLog(after)), &parsed); err != nil {
		t.Fatalf("decode connection log: %v", err)
	}
	return parsed
}

func waitForConnection(t *testing.T, controller *CoreController, host string, port int) connectionLogEntryJSON {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, entry := range readConnectionLog(t, controller, 0).Entries {
			if entry.Host == host && entry.Port == port {
				return entry
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %s:%d in connection log: %+v", host, port, readConnectionLog(t, controller, 0).Entries)
	return connectionLogEntryJSON{}
}

func serverPort(t *testing.T, rawURL string) int {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return port
}

func TestConnectionLogNamesTheSniffedDomainOfAConnectionMadeByIp(t *testing.T) {
	controller := NewCoreController(&dummyCallbackHandler{})
	controller.SetConnectionLogEnabled(true)
	socksPort := startLoggingCore(t, controller, t.TempDir(), "error")
	server := newOkServer(t)

	before := time.Now().UnixMilli()
	requestHostThroughSocks(t, socksPort, server, "sniffed.test")

	entry := waitForConnection(t, controller, "sniffed.test", serverPort(t, server.URL))
	if entry.Outbound != "direct" || entry.Network != "tcp" {
		t.Fatalf("unexpected entry: %+v", entry)
	}
	if entry.Time < before || entry.Time > time.Now().UnixMilli() {
		t.Fatalf("entry time %d is outside the request", entry.Time)
	}
}

func TestConnectionLogShowsTheRuleOutboundOfABlockedDomain(t *testing.T) {
	controller := NewCoreController(&dummyCallbackHandler{})
	controller.SetConnectionLogEnabled(true)
	socksPort := startLoggingCore(t, controller, t.TempDir(), "error")
	server := newOkServer(t)

	requestHostThroughSocks(t, socksPort, server, "blocked.test")

	entry := waitForConnection(t, controller, "blocked.test", serverPort(t, server.URL))
	if entry.Outbound != "block" {
		t.Fatalf("unexpected outbound: %+v", entry)
	}
}

func TestConnectionLogKeepsTheIpWhenNothingCouldBeSniffed(t *testing.T) {
	controller := NewCoreController(&dummyCallbackHandler{})
	controller.SetConnectionLogEnabled(true)
	socksPort := startLoggingCore(t, controller, t.TempDir(), "error")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	target := listener.Addr().(*net.TCPAddr)

	connection := connectThroughSocks(t, socksPort, target)
	defer connection.Close()
	if _, err := connection.Write([]byte("not a sniffable protocol\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	waitForConnection(t, controller, "127.0.0.1", target.Port)
}

func TestConnectionLogRecordsNothingWhileDisabled(t *testing.T) {
	controller := NewCoreController(&dummyCallbackHandler{})
	directory := t.TempDir()
	socksPort := startLoggingCore(t, controller, directory, "error")
	server := newOkServer(t)

	requestHostThroughSocks(t, socksPort, server, "quiet.test")
	waitForFileText(t, filepath.Join(directory, "access.log"), strings.TrimPrefix(server.URL, "http://"))

	if entries := readConnectionLog(t, controller, 0).Entries; len(entries) != 0 {
		t.Fatalf("expected no entries, got %+v", entries)
	}
}

func TestConnectionLogCanBeSwitchedOnWhileCoreRuns(t *testing.T) {
	controller := NewCoreController(&dummyCallbackHandler{})
	socksPort := startLoggingCore(t, controller, t.TempDir(), "error")
	controller.SetConnectionLogEnabled(true)
	server := newOkServer(t)

	requestHostThroughSocks(t, socksPort, server, "late.test")

	waitForConnection(t, controller, "late.test", serverPort(t, server.URL))
}

func TestConnectionLogLeavesTheConfiguredLogFilesAlone(t *testing.T) {
	controller := NewCoreController(&dummyCallbackHandler{})
	controller.SetConnectionLogEnabled(true)
	directory := t.TempDir()
	socksPort := startLoggingCore(t, controller, directory, "error")
	server := newOkServer(t)

	requestHostThroughSocks(t, socksPort, server, "private.test")
	waitForConnection(t, controller, "private.test", serverPort(t, server.URL))

	content, err := os.ReadFile(filepath.Join(directory, "error.log"))
	if err != nil {
		t.Fatalf("read error log: %v", err)
	}
	if strings.Contains(string(content), "[Info]") {
		t.Fatalf("Info lines reached an error-level log:\n%s", content)
	}
}

func TestConnectionLogSurvivesAProbeAndDoesNotListItsTraffic(t *testing.T) {
	controller := NewCoreController(&dummyCallbackHandler{})
	controller.SetConnectionLogEnabled(true)
	directory := t.TempDir()
	socksPort := startLoggingCore(t, controller, directory, "error")

	probeTarget := newOkServer(t)
	probeConfig := fmt.Sprintf(`{
		"log": {"loglevel": "error", "access": %q},
		"outbounds": [{"tag": "direct", "protocol": "freedom"}]
	}`, filepath.Join(directory, "access.log"))
	if _, err := MeasureOutboundDelay(probeConfig, probeTarget.URL); err != nil {
		t.Fatalf("MeasureOutboundDelay: %v", err)
	}

	server := newOkServer(t)
	requestHostThroughSocks(t, socksPort, server, "after-probe.test")
	waitForConnection(t, controller, "after-probe.test", serverPort(t, server.URL))

	for _, entry := range readConnectionLog(t, controller, 0).Entries {
		if entry.Port == serverPort(t, probeTarget.URL) {
			t.Fatalf("probe traffic was listed: %+v", entry)
		}
	}
}

func TestConnectionLogIsClearedByANewSession(t *testing.T) {
	controller := NewCoreController(&dummyCallbackHandler{})
	controller.SetConnectionLogEnabled(true)
	socksPort := startLoggingCore(t, controller, t.TempDir(), "error")
	server := newOkServer(t)
	requestHostThroughSocks(t, socksPort, server, "old-session.test")
	waitForConnection(t, controller, "old-session.test", serverPort(t, server.URL))
	if err := controller.StopLoop(); err != nil {
		t.Fatalf("StopLoop: %v", err)
	}

	startLoggingCore(t, controller, t.TempDir(), "error")

	if entries := readConnectionLog(t, controller, 0).Entries; len(entries) != 0 {
		t.Fatalf("expected an empty log, got %+v", entries)
	}
}

func accepted(to string, detour string) *corecommlog.AccessMessage {
	return &corecommlog.AccessMessage{To: to, Status: corecommlog.AccessAccepted, Detour: detour}
}

func TestConnectionLogReadsOnlyEntriesAfterTheGivenSequence(t *testing.T) {
	recorder := newConnectionRecorder()
	recorder.record(accepted("tcp:one.test:443", "in >> proxy"))
	recorder.record(accepted("tcp:two.test:443", "in -> direct"))

	var first connectionLogJSON
	if err := json.Unmarshal([]byte(recorder.read(0)), &first); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(first.Entries) != 2 || first.Seq != first.Entries[1].Seq {
		t.Fatalf("unexpected first read: %+v", first)
	}

	recorder.record(accepted("tcp:three.test:443", "in ==> proxy"))
	var second connectionLogJSON
	if err := json.Unmarshal([]byte(recorder.read(first.Seq)), &second); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(second.Entries) != 1 || second.Entries[0].Host != "three.test" {
		t.Fatalf("unexpected second read: %+v", second)
	}
}

func TestConnectionLogKeepsOnlyTheNewestEntries(t *testing.T) {
	recorder := newConnectionRecorder()
	for index := 0; index < connectionLogCapacity+10; index++ {
		recorder.record(accepted(fmt.Sprintf("tcp:host%d.test:443", index), "in >> proxy"))
	}

	var log connectionLogJSON
	if err := json.Unmarshal([]byte(recorder.read(0)), &log); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(log.Entries) != connectionLogCapacity {
		t.Fatalf("expected %d entries, got %d", connectionLogCapacity, len(log.Entries))
	}
	if log.Entries[0].Host != "host10.test" {
		t.Fatalf("oldest kept entry: %+v", log.Entries[0])
	}
}

func TestConnectionLogUnderstandsEveryInboundsDestinationForm(t *testing.T) {
	cases := []struct {
		to      string
		host    string
		port    int
		network string
	}{
		{"tcp:example.test:443", "example.test", 443, "tcp"},
		{"udp:1.1.1.1:53", "1.1.1.1", 53, "udp"},
		{"tcp:[2001:db8::1]:443", "2001:db8::1", 443, "tcp"},
		{"//ws.example.test:443", "ws.example.test", 443, "tcp"},
		{"http://plain.example.test/path?q=1", "plain.example.test", 80, "tcp"},
		{"http://plain.example.test:8080/", "plain.example.test", 8080, "tcp"},
	}
	for _, testCase := range cases {
		recorder := newConnectionRecorder()
		recorder.record(accepted(testCase.to, "in >> proxy"))
		var log connectionLogJSON
		if err := json.Unmarshal([]byte(recorder.read(0)), &log); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(log.Entries) != 1 {
			t.Fatalf("%s: no entry", testCase.to)
		}
		entry := log.Entries[0]
		if entry.Host != testCase.host || entry.Port != testCase.port || entry.Network != testCase.network {
			t.Fatalf("%s: %+v", testCase.to, entry)
		}
		if entry.Outbound != "proxy" {
			t.Fatalf("%s: outbound %q", testCase.to, entry.Outbound)
		}
	}
}
