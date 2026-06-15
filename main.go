package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

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
	flagVersion     bool
)

// version is the current release number.
const version = "0.1.0"

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
	flag.BoolVar(&flagVersion, "version", false, "Print version and exit")
}

// ============================================================================
// Constants
// ============================================================================

const (
	maxDataSize = 8192
	dirInbound  = 0
	dirOutbound = 1
)

// expectedEventSize is the binary size of pugiEvent.
// Used as a fast-path guard against decoding short/lost-sample records.
var expectedEventSize = binary.Size(pugiEvent{})

// minEventSize is the fixed header size (everything before data[]).
// Events shorter than this are corrupt / lost-sample records.
var minEventSize = expectedEventSize - maxDataSize


// ============================================================================
// HTTP message parser
// ============================================================================

// connKey uniquely identifies a connection direction.
type connKey struct {
	pid       uint32
	fd        uint32
	direction uint32
}

// pairKey groups both directions of a connection (pid + fd).
type pairKey struct {
	pid uint32
	fd  uint32
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
	ts         time.Time // kernel timestamp from BPF event
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

// reqFilterActive returns true when request-specific filters are set.
// Responses have no path or method — without pairing they'd all pass.
func (f *filter) reqFilterActive() bool {
	return f.pathPrefix != "" || f.method != ""
}

// respFilterActive returns true when response-specific filters are set.
// When active, IN messages are buffered and only printed together with
// a matching OUT response — so you see the request that caused a 500,
// not just the 500 itself.
func (f *filter) respFilterActive() bool {
	return f.statusCode > 0
}

func (f *filter) match(msg *httpMsg) bool {
	// Path prefix filter — only applies to requests (responses have no path)
	if f.pathPrefix != "" && msg.isRequest && !strings.HasPrefix(msg.path, f.pathPrefix) {
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

	// Status code filter — only applies to responses (IN has no status code)
	if f.statusCode > 0 && !msg.isRequest && msg.statusCode != f.statusCode {
		return false
	}

	// Body keyword filter
	if f.bodyKeyword != "" && !bytes.Contains(msg.body, []byte(f.bodyKeyword)) {
		// When response-side pairing is active, IN messages are stashed
		// and printed only if the paired OUT matches. Body filtering
		// on IN would prematurely drop stashed requests before their
		// matching OUT arrives.
		if msg.isRequest && f.respFilterActive() {
			// pass — IN printed only when paired OUT matches
		} else {
			return false
		}
	}

	return true
}

// ============================================================================
// Collector
// ============================================================================

type collector struct {
	conns       map[connKey]*connBuf
	reqPending  map[pairKey]int          // +1 per matched request, -1 per paired response (OUT→IN)
	pendingReqs map[pairKey][]*httpMsg   // buffered IN for response-side pairing (IN→OUT)
	filter      filter
	maxBody     int
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
		conns:       make(map[connKey]*connBuf),
		reqPending:  make(map[pairKey]int),
		pendingReqs: make(map[pairKey][]*httpMsg),
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
func (c *collector) feed(pid, fd, direction uint32, data []byte, ts time.Time) {
	ck := connKey{pid, fd, direction}
	cb, ok := c.conns[ck]
	if !ok {
		cb = &connBuf{}
		c.conns[ck] = cb
	}
	// If the buffer has stale data (idle > 5 s since last feed),
	// the previous connection on this fd probably closed and the fd
	// was recycled. Clear it so old fragments don't corrupt the new
	// stream. Keep-alive connections refill within milliseconds.
	if len(cb.buf) > 0 && time.Since(cb.last) > 5*time.Second {
		cb.buf = nil
	}
	cb.last = time.Now()
	cb.buf = append(cb.buf, data...)

	// Extract as many complete HTTP messages as possible
	for {
		msg, consumed := parseHTTP(cb.buf, ck, ts)
		if msg == nil {
			if consumed > 0 {
				cb.buf = cb.buf[consumed:] // skip garbage prefix
			}
			break
		}
		cb.buf = cb.buf[consumed:]

		if c.filter.match(msg) {
			pk := pairKey{msg.conn.pid, msg.conn.fd}

			// ── Response-side pairing (IN → OUT) ──────────────────
			// When --status is active, buffer IN requests and only
			// print them when the matching OUT response arrives.
			if msg.isRequest && c.filter.respFilterActive() {
				q := c.pendingReqs[pk]
				if len(q) < 16 {
					c.pendingReqs[pk] = append(q, msg)
				}
				continue // don't print yet
			}

			// ── Request-side pairing (OUT → IN) ──────────────────
			// When --path-prefix or --method is active, suppress
			// responses that don't pair with a matched request.
			// Skip when respFilterActive is also active — in that
			// case the response-side pairing below handles it.
			if !msg.isRequest && c.filter.reqFilterActive() && !c.filter.respFilterActive() {
				if c.reqPending[pk] <= 0 {
					continue // no matching request pending
				}
				c.reqPending[pk]--
			}

			// ── Print ─────────────────────────────────────────────
			// Response-side: pop and print the oldest stashed IN
			// before the matching OUT.
			if !msg.isRequest && c.filter.respFilterActive() {
				if reqs := c.pendingReqs[pk]; len(reqs) > 0 {
					c.printIfVisible(reqs[0])
					c.pendingReqs[pk] = reqs[1:]
				}
			}

			c.printIfVisible(msg)

			// Track matched request so its response can pair later.
			if msg.isRequest && c.filter.reqFilterActive() {
				c.reqPending[pk]++
			}
		}

		// Response-side cleanup: when an OUT does NOT match, drop
		// the oldest stashed IN (it pairs with this non-matching OUT).
		if !msg.isRequest && c.filter.respFilterActive() && !c.filter.match(msg) {
			pk := pairKey{msg.conn.pid, msg.conn.fd}
			if reqs := c.pendingReqs[pk]; len(reqs) > 0 {
				c.pendingReqs[pk] = reqs[1:]
			}
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
		if cb.last.Before(threshold) {
			delete(c.conns, ck)
		}
	}
	// Also clean reqPending entries whose connections have been GC'd.
	// Build a set of active {pid,fd} pairs first.
	active := make(map[pairKey]bool)
	for ck := range c.conns {
		active[pairKey{ck.pid, ck.fd}] = true
	}
	for pk := range c.reqPending {
		if !active[pk] {
			delete(c.reqPending, pk)
		}
	}
	for pk := range c.pendingReqs {
		if !active[pk] {
			delete(c.pendingReqs, pk)
		}
	}
}

// reset drops all connection buffers. Called after a perf buffer overflow
// because lost events mean the TCP stream is now missing bytes and any
// in-progress HTTP parse is irretrievably corrupted.
func (c *collector) reset() {
	c.conns = make(map[connKey]*connBuf)
	c.reqPending = make(map[pairKey]int)
	c.pendingReqs = make(map[pairKey][]*httpMsg)
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

func parseHTTP(data []byte, ck connKey, ts time.Time) (*httpMsg, int) {
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
		ts:        ts,
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
			msg.body = decodeChunkedBody(data[bodyStart:bodyEnd])
			return msg, bodyEnd
		}
		// Chunked terminator not yet received — wait for more data.
		// Returning nil here (instead of consuming partial data) keeps
		// the buffer intact so subsequent keep-alive messages on the
		// same fd won't be corrupted.
		return nil, 0
	}

	// No body
	msg.body = nil
	return msg, headerEnd + 4
}

// ============================================================================
// Output formatting
// ============================================================================

// decodeChunkedBody strips HTTP chunked transfer-encoding framing.
// Input is raw chunked body bytes; output is the reassembled payload.
// Malformed chunks are silently skipped.
func decodeChunkedBody(raw []byte) []byte {
	var out []byte
	for len(raw) > 0 {
		// Find end of chunk-size line (hex size [;extension] \r\n)
		cr := bytes.IndexByte(raw, '\r')
		if cr == -1 {
			break
		}
		sizeStr := string(raw[:cr])
		// Strip chunk extensions (anything after ';')
		if semi := strings.IndexByte(sizeStr, ';'); semi != -1 {
			sizeStr = sizeStr[:semi]
		}
		sizeStr = strings.TrimSpace(sizeStr)
		var sz int64
		if _, parseErr := fmt.Sscanf(sizeStr, "%x", &sz); parseErr != nil || sz < 0 {
			break
		}
		if sz == 0 {
			break // final chunk
		}
		// Skip \r\n after chunk size
		dataStart := cr + 2
		dataEnd := dataStart + int(sz)
		if dataEnd+2 > len(raw) {
			break // incomplete chunk
		}
		out = append(out, raw[dataStart:dataEnd]...)
		raw = raw[dataEnd+2:] // skip chunk-data + trailing \r\n
	}
	return out
}

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

// ============================================================================
// Body decoding
// ============================================================================

// decodeBody decompresses the body if Content-Encoding is set, otherwise
// returns it unchanged. Only gzip is supported at present.
func decodeBody(msg *httpMsg) []byte {
	enc := strings.ToLower(msg.header.Get("Content-Encoding"))
	if enc == "" {
		return msg.body
	}
	// gzip is the common case; deflate without a zlib wrapper is rare
	// in practice and not supported here.
	if strings.Contains(enc, "gzip") {
		r, err := gzip.NewReader(bytes.NewReader(msg.body))
		if err != nil {
			return msg.body // fall back to raw bytes
		}
		defer r.Close()
		d, err := io.ReadAll(r)
		if err != nil {
			return msg.body
		}
		return d
	}
	return msg.body
}

func (c *collector) printMsg(msg *httpMsg) {
	clr := activeColors()

	dirLabel := "IN"
	dirColor := clr.green
	if msg.conn.direction == dirOutbound {
		dirLabel = "OUT"
		dirColor = clr.yellow
	}

	// Direction badge + timestamp (kernel event time, not print time)
	fmt.Printf("%s[%s]%s %s%s%s pid=%-5d fd=%-4d\n",
		dirColor, dirLabel, clr.reset,
		clr.dim, msg.ts.Format("15:04:05.000"), clr.reset,
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
		fmt.Printf("  %s%s%s %s%d %s%s\n",
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
		display := decodeBody(msg)
		decoded := len(display)
		bodyNote := fmt.Sprintf("body (%d bytes)", len(msg.body))
		if decoded != len(msg.body) {
			bodyNote += fmt.Sprintf(" → %d decoded", decoded)
		}
		if decoded > c.maxBody {
			display = display[:c.maxBody]
		}
		fmt.Printf("  %s── %s ──%s\n", clr.dim, bodyNote, clr.reset)
		fmt.Print(string(display))
		if decoded > c.maxBody {
			fmt.Printf("%s\n  ... truncated (%d bytes total)%s\n",
				clr.dim, decoded, clr.reset)
		}
	}
	fmt.Println()
}

// printIfVisible prints the message only if its direction matches the
// configured --direction flag. When direction is "both" (default) all
// messages pass through; "inbound" only prints IN; "outbound" only OUT.
//
// This is separate from filter.match() — direction is a display control,
// not a data filter.
func (c *collector) printIfVisible(msg *httpMsg) {
	switch c.filter.direction {
	case "inbound":
		if msg.conn.direction != dirInbound {
			return
		}
	case "outbound":
		if msg.conn.direction != dirOutbound {
			return
		}
	}
	c.printMsg(msg)
}

// ============================================================================
// eBPF event decoding
// ============================================================================

// processEvent decodes a raw perf event record into an pugiEvent
// (generated by bpf2go) and feeds the contained data to the HTTP collector.
//
// Since the BPF side submits variable-length events (only the used portion
// of data[]), RawSample may be shorter than the full pugiEvent. We pad
// with zeros before decoding — the padding lands past DataLen and is
// harmless.
func (c *collector) processEvent(raw []byte) error {
	if len(raw) < expectedEventSize {
		padded := make([]byte, expectedEventSize)
		copy(padded, raw)
		raw = padded
	}
	var ev pugiEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return fmt.Errorf("decoding event: %w", err)
	}

	if ev.DataLen > maxDataSize {
		ev.DataLen = maxDataSize
	}

	data := ev.Data[:ev.DataLen]
	// Capture wall-clock time at decode time — this is ~µs after the
	// syscall completed and serves as the event timestamp for output.
	c.feed(ev.Pid, ev.Fd, ev.Direction, data, time.Now())
	return nil
}

// ============================================================================
// eBPF program lookup helpers
// ============================================================================

func enterProgByName(objs *pugiObjects, name string) (*ebpf.Program, bool) {
	switch name {
	case "read":
		return objs.TpEnterRead, true
	case "readv":
		return objs.TpEnterReadv, true
	case "write":
		return objs.TpEnterWrite, true
	case "writev":
		return objs.TpEnterWritev, true
	case "recvfrom":
		return objs.TpEnterRecvfrom, true
	case "recvmsg":
		return objs.TpEnterRecvmsg, true
	case "sendto":
		return objs.TpEnterSendto, true
	case "sendmsg":
		return objs.TpEnterSendmsg, true
	}
	return nil, false
}

func exitProgByName(objs *pugiObjects, name string) (*ebpf.Program, bool) {
	switch name {
	case "read":
		return objs.TpExitRead, true
	case "readv":
		return objs.TpExitReadv, true
	case "write":
		return objs.TpExitWrite, true
	case "writev":
		return objs.TpExitWritev, true
	case "recvfrom":
		return objs.TpExitRecvfrom, true
	case "recvmsg":
		return objs.TpExitRecvmsg, true
	case "sendto":
		return objs.TpExitSendto, true
	case "sendmsg":
		return objs.TpExitSendmsg, true
	}
	return nil, false
}

// ============================================================================
// Main
// ============================================================================

func main() {
	flag.Parse()

	if flagVersion {
		fmt.Println("pugi", version)
		os.Exit(0)
	}

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

Output:
  --direction <DIR>    inbound, outbound, or both (default: both)
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
	traces := []string{"read", "readv", "write", "writev",
		"recvfrom", "recvmsg", "sendto", "sendmsg"}
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
			log.Printf("⚠  skip sys_enter_%s: %v", name, err)
			continue
		}
		links = append(links, enterTP)

		exitTP, err := link.Tracepoint("syscalls", "sys_exit_"+name, exitProg, nil)
		if err != nil {
			log.Printf("⚠  skip sys_exit_%s: %v", name, err)
			continue
		}
		links = append(links, exitTP)
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	log.Printf("Attached %d tracepoints — capturing HTTP traffic...", len(links))
	log.Println("   Press Ctrl+C to stop, Ctrl+L to clear screen\n")

	// Put stdin in raw mode so we can detect Ctrl+L (0x0C).
	origTermios, err := rawModeOn(int(os.Stdin.Fd()))
	if err == nil {
		defer rawModeOff(int(os.Stdin.Fd()), origTermios)
		// Keyboard shortcut goroutine: read stdin for Ctrl+L (clear screen).
		go func() {
			buf := make([]byte, 1)
			for {
				_, err := os.Stdin.Read(buf)
				if err != nil {
					return // EOF or terminal closed
				}
				if buf[0] == '\x0c' { // Ctrl+L
					fmt.Print("\033[2J\033[H")
				}
			}
		}()
	} else {
		log.Printf("⚠  can't set terminal raw mode: %v — Ctrl+L not available", err)
	}

	// Signal handling
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Perf event reader — 128 pages × 4 KB = 512 KB per CPU.
	// This fits within the default kernel.perf_event_mlock_kb (516 KB)
	// on RHEL 8 / 4.18 kernels.  Combined with variable-length events
	// (small reads use ~150 bytes instead of 8 KB), the buffer can hold
	// several hundred events per CPU before backpressure kicks in.
	rd, err := perf.NewReader(objs.Events, 128*os.Getpagesize())
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

		// Lost samples: kernel dropped events because the perf buffer
		// overflowed. Log a warning once per batch and skip decoding
		// (the RawSample is just a small lost-count struct, not a valid
		// pugiEvent).
		if record.LostSamples > 0 {
			log.Printf("⚠  perf buffer overflow: %d events lost", record.LostSamples)
			col.reset()
			continue
		}

		if len(record.RawSample) < minEventSize {
			log.Printf("⚠  short event (%d bytes, min %d) — skipping",
				len(record.RawSample), minEventSize)
			continue
		}

		if err := col.processEvent(record.RawSample); err != nil {
			log.Printf("event decode error: %v", err)
		}
	}

	log.Println("pugi stopped.")
}

// ============================================================================
// Terminal raw mode helpers — used for Ctrl+L shortcut
// ============================================================================

// rawModeOn puts the terminal fd into raw (non-canonical) mode and returns
// the original termios for later restoration. In raw mode each byte is
// delivered immediately without line buffering or echo.
func rawModeOn(fd int) (*syscall.Termios, error) {
	var orig syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		syscall.TCGETS, uintptr(unsafe.Pointer(&orig))); errno != 0 {
		return nil, fmt.Errorf("tcgetattr: %v", errno)
	}
	raw := orig
	// lflags: disable canonical mode & echo, keep ISIG so Ctrl+C still works
	raw.Lflag &^= syscall.ICANON | syscall.ECHO
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		syscall.TCSETS, uintptr(unsafe.Pointer(&raw))); errno != 0 {
		return nil, fmt.Errorf("tcsetattr: %v", errno)
	}
	return &orig, nil
}

// rawModeOff restores the terminal to its previous state.
func rawModeOff(fd int, orig *syscall.Termios) {
	if orig == nil {
		return
	}
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		syscall.TCSETS, uintptr(unsafe.Pointer(orig)))
}
