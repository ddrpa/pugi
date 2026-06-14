package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -target bpf -idirafter /usr/include" -type event pugi bpf/pugi.c

// ============================================================================
// CLI flags
// ============================================================================

var (
	flagPID         int
	flagPathPrefix  string
	flagMethod      string
	flagHeader      string
	flagStatus      int
	flagBodyKeyword string
	flagDirection   string
	flagNoColor     bool
	flagMaxBody     int
)

func init() {
	flag.IntVar(&flagPID, "pid", 0, "Target process PID (required)")
	flag.StringVar(&flagPathPrefix, "path-prefix", "", "Filter: URL path prefix (e.g. /api/v1)")
	flag.StringVar(&flagMethod, "method", "", "Filter: HTTP method (e.g. GET, POST)")
	flag.StringVar(&flagHeader, "header", "", "Filter: header match in form Key:Value")
	flag.IntVar(&flagStatus, "status", 0, "Filter: response status code (e.g. 200, 404)")
	flag.StringVar(&flagBodyKeyword, "body-contains", "", "Filter: body keyword match")
	flag.StringVar(&flagDirection, "direction", "both",
		"Traffic direction: inbound, outbound, or both")
	flag.BoolVar(&flagNoColor, "no-color", false, "Disable ANSI color output")
	flag.IntVar(&flagMaxBody, "max-body", 1024, "Max bytes of HTTP body to capture and display")
}

// ============================================================================
// Constants
// ============================================================================

const (
	maxDataSize = 8192
	dirInbound  = 0
	dirOutbound = 1
)

// ============================================================================
// HTTP message parser
// ============================================================================

// connKey uniquely identifies a connection direction.
type connKey struct {
	pid       uint32
	fd        uint32
	direction uint32
}

// connBuf accumulates TCP data for a single connection direction.
type connBuf struct {
	buf  []byte
	last time.Time
}

// httpMsg is a parsed HTTP message (request or response).
type httpMsg struct {
	isRequest  bool
	conn       connKey
	httpVer    string   // "HTTP/1.1" etc.
	method     string   // GET, POST, ...
	path       string   // /api/v1/users
	statusCode int      // 200, 404, ...
	statusText string   // OK, Not Found, ...
	header     http.Header
	body       []byte
}

// ============================================================================
// Filter
// ============================================================================

type filter struct {
	pathPrefix  string
	method      string
	headerKey   string
	headerVal   string
	statusCode  int
	bodyKeyword string
	direction   string // "inbound", "outbound", "both"
}

func (f *filter) match(msg *httpMsg) bool {
	// Direction filter
	switch f.direction {
	case "inbound":
		if msg.conn.direction != dirInbound {
			return false
		}
	case "outbound":
		if msg.conn.direction != dirOutbound {
			return false
		}
	}

	// Path prefix filter
	if f.pathPrefix != "" && !strings.HasPrefix(msg.path, f.pathPrefix) {
		return false
	}

	// Method filter
	if f.method != "" && !strings.EqualFold(msg.method, f.method) {
		return false
	}

	// Header filter: key must exist; if value given, it must contain the value
	if f.headerKey != "" {
		val := msg.header.Get(f.headerKey)
		if val == "" {
			return false
		}
		if f.headerVal != "" && !strings.Contains(val, f.headerVal) {
			return false
		}
	}

	// Status code filter
	if f.statusCode > 0 && msg.statusCode != f.statusCode {
		return false
	}

	// Body keyword filter
	if f.bodyKeyword != "" && !bytes.Contains(msg.body, []byte(f.bodyKeyword)) {
		return false
	}

	return true
}

// ============================================================================
// Collector
// ============================================================================

type collector struct {
	conns   map[connKey]*connBuf
	filter  filter
	maxBody int
}

func newCollector() *collector {
	hk, hv := "", ""
	if flagHeader != "" {
		parts := strings.SplitN(flagHeader, ":", 2)
		if len(parts) == 2 {
			hk = strings.TrimSpace(parts[0])
			hv = strings.TrimSpace(parts[1])
		}
	}

	return &collector{
		conns: make(map[connKey]*connBuf),
		filter: filter{
			pathPrefix:  flagPathPrefix,
			method:      strings.ToUpper(flagMethod),
			headerKey:   hk,
			headerVal:   hv,
			statusCode:  flagStatus,
			bodyKeyword: flagBodyKeyword,
			direction:   flagDirection,
		},
		maxBody: flagMaxBody,
	}
}

// feed processes a raw data chunk from eBPF.
func (c *collector) feed(pid, fd, direction uint32, data []byte) {
	ck := connKey{pid, fd, direction}
	cb, ok := c.conns[ck]
	if !ok {
		cb = &connBuf{}
		c.conns[ck] = cb
	}
	cb.last = time.Now()
	cb.buf = append(cb.buf, data...)

	// Extract as many complete HTTP messages as possible
	for {
		msg, consumed := parseHTTP(cb.buf, ck)
		if msg == nil {
			if consumed > 0 {
				cb.buf = cb.buf[consumed:] // skip garbage prefix
			}
			break
		}
		cb.buf = cb.buf[consumed:]

		if c.filter.match(msg) {
			c.printMsg(msg)
		}
	}

	// Cap buffer to prevent unbounded growth
	if len(cb.buf) > 65536 {
		cb.buf = cb.buf[len(cb.buf)-32768:]
	}
}

func (c *collector) gc() {
	threshold := time.Now().Add(-60 * time.Second)
	for ck, cb := range c.conns {
		if cb.last.Before(threshold) && len(cb.buf) == 0 {
			delete(c.conns, ck)
		}
	}
}

// ============================================================================
// HTTP parser
//
// parseHTTP tries to extract one complete HTTP message from the front of data.
// Returns:
//
//	msg      — parsed message, or nil if not enough data / not HTTP
//	consumed — bytes to discard from the front of the buffer
// ============================================================================

// recognized HTTP methods (RFC 7231 + PATCH from RFC 5789)
var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "),
	[]byte("PATCH "), []byte("HEAD "), []byte("OPTIONS "), []byte("CONNECT "),
	[]byte("TRACE "),
}

func parseHTTP(data []byte, ck connKey) (*httpMsg, int) {
	if len(data) < 12 {
		return nil, 0 // need at least minimal start line
	}

	isReq := false
	for _, m := range httpMethods {
		if bytes.HasPrefix(data, m) {
			isReq = true
			break
		}
	}
	isResp := !isReq && bytes.HasPrefix(data, []byte("HTTP/"))

	if !isReq && !isResp {
		// Not HTTP — skip one byte and retry on the next call
		return nil, 1
	}

	// Locate end of headers
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return nil, 0 // headers incomplete, wait for more data
	}

	headerBlock := data[:headerEnd]
	headerStr := string(headerBlock)
	lines := strings.Split(headerStr, "\r\n")
	if len(lines) == 0 {
		return nil, headerEnd + 4
	}

	msg := &httpMsg{
		isRequest: isReq,
		conn:      ck,
		header:    http.Header{},
	}

	// --- Parse start line ---
	startLine := lines[0]

	if isReq {
		// "METHOD /path HTTP/1.1"
		parts := strings.SplitN(startLine, " ", 3)
		if len(parts) < 2 {
			return nil, headerEnd + 4
		}
		msg.method = parts[0]
		msg.path = parts[1]
		if len(parts) >= 3 {
			msg.httpVer = parts[2]
		}
	} else {
		// "HTTP/1.1 200 OK"
		parts := strings.SplitN(startLine, " ", 3)
		if len(parts) < 2 {
			return nil, headerEnd + 4
		}
		msg.httpVer = parts[0]
		fmt.Sscanf(parts[1], "%d", &msg.statusCode)
		if len(parts) >= 3 {
			msg.statusText = parts[2]
		}
	}

	// --- Parse headers ---
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		kv := strings.SplitN(line, ": ", 2)
		if len(kv) == 2 {
			msg.header.Add(kv[0], kv[1])
		}
	}

	// --- Determine body ---
	bodyStart := headerEnd + 4
	contentLen := 0
	if cl := msg.header.Get("Content-Length"); cl != "" {
		fmt.Sscanf(cl, "%d", &contentLen)
	}
	chunked := strings.EqualFold(msg.header.Get("Transfer-Encoding"), "chunked")

	if contentLen > 0 {
		bodyEnd := bodyStart + contentLen
		if bodyEnd > len(data) {
			return nil, 0 // body not fully received
		}
		msg.body = data[bodyStart:bodyEnd]
		return msg, bodyEnd
	}

	if chunked {
		// "0\r\n\r\n" marks end of chunked body
		if term := bytes.Index(data[bodyStart:], []byte("0\r\n\r\n")); term != -1 {
			bodyEnd := bodyStart + term + 5
			msg.body = data[bodyStart:bodyEnd]
			return msg, bodyEnd
		}
		// Best effort: consume everything received so far
		msg.body = data[bodyStart:]
		return msg, len(data)
	}

	// No body
	msg.body = nil
	return msg, headerEnd + 4
}

// ============================================================================
// Output formatting
// ============================================================================

type colorMode struct {
	reset, magenta, cyan, yellow, green, red, blue, white, dim string
}

func activeColors() colorMode {
	if flagNoColor {
		return colorMode{}
	}
	return colorMode{
		reset:   "\033[0m",
		magenta: "\033[35m",
		cyan:    "\033[36m",
		yellow:  "\033[33m",
		green:   "\033[32m",
		red:     "\033[31m",
		blue:    "\033[34m",
		white:   "\033[37m",
		dim:     "\033[2m",
	}
}

func (c *collector) printMsg(msg *httpMsg) {
	clr := activeColors()

	dirLabel := "IN"
	dirColor := clr.green
	if msg.conn.direction == dirOutbound {
		dirLabel = "OUT"
		dirColor = clr.yellow
	}

	// Direction badge + timestamp
	fmt.Printf("%s[%s]%s %s%s%s pid=%-5d fd=%-4d\n",
		dirColor, dirLabel, clr.reset,
		clr.dim, time.Now().Format("15:04:05.000"), clr.reset,
		msg.conn.pid, msg.conn.fd)

	// Start line
	if msg.isRequest {
		fmt.Printf("  %s%s%s %s%s%s %s%s%s\n",
			clr.cyan, msg.method, clr.reset,
			clr.white, msg.path, clr.reset,
			clr.dim, msg.httpVer, clr.reset)
	} else {
		codeColor := clr.green
		if msg.statusCode >= 400 {
			codeColor = clr.red
		} else if msg.statusCode >= 300 {
			codeColor = clr.yellow
		}
		fmt.Printf("  %s%s%s %s%d %s%s%s\n",
			clr.dim, msg.httpVer, clr.reset,
			codeColor, msg.statusCode, msg.statusText, clr.reset)
	}

	// Headers
	for key, vals := range msg.header {
		for _, v := range vals {
			fmt.Printf("  %s%s:%s %s\n", clr.blue, key, clr.reset, v)
		}
	}

	// Body
	if len(msg.body) > 0 {
		display := msg.body
		if len(display) > c.maxBody {
			display = display[:c.maxBody]
		}
		fmt.Printf("  %s── body (%d bytes) ──%s\n", clr.dim, len(msg.body), clr.reset)
		fmt.Print(string(display))
		if len(msg.body) > c.maxBody {
			fmt.Printf("%s\n  ... truncated (%d bytes total)%s\n",
				clr.dim, len(msg.body), clr.reset)
		}
	}
	fmt.Println()
}

// ============================================================================
// eBPF event decoding
// ============================================================================

// processEvent decodes a raw ring-buffer record into an pugiEvent
// (generated by bpf2go) and feeds the contained data to the HTTP collector.
func (c *collector) processEvent(raw []byte) error {
	var ev pugiEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return fmt.Errorf("decoding event: %w", err)
	}

	if ev.DataLen > maxDataSize {
		ev.DataLen = maxDataSize
	}

	data := ev.Data[:ev.DataLen]
	c.feed(ev.Pid, ev.Fd, ev.Direction, data)
	return nil
}

// ============================================================================
// eBPF program lookup helpers
// ============================================================================

func enterProgByName(objs *pugiObjects, name string) (*ebpf.Program, bool) {
	switch name {
	case "read":
		return objs.TpEnterRead, true
	case "write":
		return objs.TpEnterWrite, true
	case "recvfrom":
		return objs.TpEnterRecvfrom, true
	case "sendto":
		return objs.TpEnterSendto, true
	}
	return nil, false
}

func exitProgByName(objs *pugiObjects, name string) (*ebpf.Program, bool) {
	switch name {
	case "read":
		return objs.TpExitRead, true
	case "write":
		return objs.TpExitWrite, true
	case "recvfrom":
		return objs.TpExitRecvfrom, true
	case "sendto":
		return objs.TpExitSendto, true
	}
	return nil, false
}

// ============================================================================
// Main
// ============================================================================

func main() {
	flag.Parse()

	if flagPID <= 0 {
		fmt.Fprintf(os.Stderr, `pugi — eBPF-based HTTP traffic observer

Usage:
  pugi --pid <PID> [options]

Required:
  --pid <PID>          Target process PID

Filters:
  --path-prefix <path> Filter by URL path prefix (e.g. /api/v1)
  --method <METHOD>    Filter by HTTP method (e.g. GET, POST)
  --header <K:V>       Filter by header (e.g. Content-Type:application/json)
  --status <CODE>      Filter by response status code (e.g. 200, 404)
  --body-contains <S>  Filter by body keyword
  --direction <DIR>    inbound, outbound, or both (default: both)

Output:
  --no-color           Disable ANSI color
  --max-body <N>       Max body bytes to display (default: 1024)

Examples:
  pugi --pid 1234
  pugi --pid 1234 --path-prefix /api/v1 --method POST
  pugi --pid 1234 --direction inbound --status 500
`)
		os.Exit(1)
	}

	// Remove memlock limit (required on older kernels)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// Load eBPF programs and maps
	objs := pugiObjects{}
	if err := loadPugiObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("eBPF verifier error:\n%+v", ve)
		}
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Configure target PID
	pidKey := uint32(0)
	targetPID := uint32(flagPID)
	if err := objs.TargetPid.Put(&pidKey, &targetPID); err != nil {
		log.Fatalf("Failed to set target PID: %v", err)
	}
	log.Printf("Watching PID %d", flagPID)

	// Attach syscall tracepoints
	traces := []string{"read", "write", "recvfrom", "sendto"}
	var links []link.Link

	for _, name := range traces {
		enterProg, _ := enterProgByName(&objs, name)
		exitProg, _ := exitProgByName(&objs, name)
		if enterProg == nil || exitProg == nil {
			log.Printf("⚠  skip %s: program not found", name)
			continue
		}

		enterTP, err := link.Tracepoint("syscalls", "sys_enter_"+name, enterProg, nil)
		if err != nil {
			log.Fatalf("Failed to attach sys_enter_%s: %v", name, err)
		}
		links = append(links, enterTP)

		exitTP, err := link.Tracepoint("syscalls", "sys_exit_"+name, exitProg, nil)
		if err != nil {
			log.Fatalf("Failed to attach sys_exit_%s: %v", name, err)
		}
		links = append(links, exitTP)
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	log.Printf("Attached %d tracepoints — capturing HTTP traffic...", len(links))
	log.Println("   Press Ctrl+C to stop\n")

	// Signal handling
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Ring buffer reader
	rd, err := perf.NewReader(objs.Events, 4096)
	if err != nil {
		log.Fatalf("Failed to create perf event reader: %v", err)
	}
	defer rd.Close()

	col := newCollector()

	// Background GC of stale connection buffers
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				col.gc()
			}
		}
	}()

	// Main event loop
	//
	// Start a goroutine to close the perf reader on context cancellation,
	// which unblocks rd.Read() so the main loop can exit via ErrClosed.
	go func() {
		<-ctx.Done()
		// Closing the reader makes rd.Read() return perf.ErrClosed
		// immediately, breaking out of the main event loop.
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				break
			}
			log.Printf("perf event read error: %v", err)
			continue
		}

		if err := col.processEvent(record.RawSample); err != nil {
			log.Printf("event decode error: %v", err)
		}
	}

	log.Println("pugi stopped.")
}
