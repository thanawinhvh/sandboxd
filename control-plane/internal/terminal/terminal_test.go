package terminal

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- handshake ------------------------------------------------------

// TestAcceptKey checks the RFC 6455 §1.3 example vector.
func TestAcceptKey(t *testing.T) {
	if got, want := acceptKey("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="; got != want {
		t.Fatalf("acceptKey = %q, want %q", got, want)
	}
}

// TestAcceptHTTP runs the real handshake against an httptest server
// with a raw TCP client.
func TestAcceptHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := Accept(w, r)
		if err != nil {
			return // Accept already wrote the HTTP error
		}
		defer ws.Close()
		// Echo one message back, then end the session.
		op, msg, err := ws.ReadMessage()
		if err != nil {
			return
		}
		if op == opBinary {
			_ = ws.WriteBinary(msg)
		}
		_ = ws.WriteClose()
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	key := "dGhlIHNhbXBsZSBub25jZQ=="
	req := "GET /v1/sandboxes/x/terminal HTTP/1.1\r\n" +
		"Host: x\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("status = %q, want 101", strings.TrimSpace(status))
	}
	var accept string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
		// Match the name case-insensitively but keep the value
		// verbatim (base64 is case-sensitive).
		if i := strings.Index(line, ":"); i >= 0 &&
			strings.EqualFold(strings.TrimSpace(line[:i]), "sec-websocket-accept") {
			accept = strings.TrimSpace(line[i+1:])
		}
	}
	if accept != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("accept = %q", accept)
	}

	// Masked binary frame from the client; the server echoes it.
	clientWrite(t, conn, opBinary, []byte("hello-ws"))
	op, payload := clientRead(t, br)
	if op != opBinary || string(payload) != "hello-ws" {
		t.Fatalf("echo op=%d payload=%q", op, payload)
	}
	// Then the server close handshake.
	if op, _ := clientRead(t, br); op != opClose {
		t.Fatalf("op = %d, want close", op)
	}
}

// TestAcceptRejectsPlainHTTP ensures a non-upgrade request gets a
// plain HTTP error (no hijack).
func TestAcceptRejectsPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := Accept(w, r); err == nil {
			t.Error("Accept accepted a plain HTTP request")
		}
	}))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// --- framing --------------------------------------------------------

// TestFrameFragmentation feeds a message in two frames plus an
// interleaved ping; ReadMessage must reassemble and answer pong.
func TestFrameFragmentation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ws := &Conn{conn: server, br: bufio.NewReader(server)}

	type result struct {
		op      int
		payload []byte
		err     error
	}
	resCh := make(chan result, 1)
	go func() {
		op, payload, err := ws.ReadMessage()
		resCh <- result{op, payload, err}
	}()

	// First fragment (FIN=0, binary), then a ping, then the tail.
	// Written from a goroutine: net.Pipe is unbuffered, so the
	// writes interleave with the server's pong reply.
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		clientWriteFrag(t, client, false, opBinary, []byte("hel"))
		clientWrite(t, client, opPing, []byte("p"))
		clientWriteFrag(t, client, true, opCont, []byte("lo"))
	}()
	defer func() { <-writeDone }()

	// The pong reply arrives before the reassembled message.
	cr := bufio.NewReader(client)
	if op, p := clientRead(t, cr); op != opPong || string(p) != "p" {
		t.Fatalf("pong op=%d payload=%q", op, p)
	}
	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatal(res.err)
		}
		if res.op != opBinary || string(res.payload) != "hello" {
			t.Fatalf("op=%d payload=%q", res.op, res.payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadMessage timed out")
	}
}

// TestCloseHandshake ensures a client close is echoed and reported
// as ErrClosed.
func TestCloseHandshake(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ws := &Conn{conn: server, br: bufio.NewReader(server)}

	resCh := make(chan error, 1)
	go func() {
		_, _, err := ws.ReadMessage()
		resCh <- err
	}()
	clientWrite(t, client, opClose, nil)
	if op, _ := clientRead(t, bufio.NewReader(client)); op != opClose {
		t.Fatalf("op = %d, want echoed close", op)
	}
	select {
	case err := <-resCh:
		if err != ErrClosed {
			t.Fatalf("err = %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadMessage timed out")
	}
}

// --- sessions (pipe mode, local commands — no Docker) ----------------

// TestServeEcho runs `cat` through a full session: stdin in, stdout
// out, resize tolerated, close ends the session.
func TestServeEcho(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	ws := &Conn{conn: server, br: bufio.NewReader(server)}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- Serve(ws, Config{Cmd: []string{"cat"}})
	}()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	cr := bufio.NewReader(client)

	clientWrite(t, client, opBinary, []byte("hello-term\n"))
	if op, p := clientRead(t, cr); op != opBinary || string(p) != "hello-term\n" {
		t.Fatalf("echo op=%d payload=%q", op, p)
	}

	// Resize is accepted (a no-op on pipes, must not break).
	clientWrite(t, client, opText, []byte(`{"type":"resize","cols":120,"rows":40}`))
	clientWrite(t, client, opBinary, []byte("still-alive\n"))
	if op, p := clientRead(t, cr); op != opBinary || string(p) != "still-alive\n" {
		t.Fatalf("echo op=%d payload=%q", op, p)
	}

	// Client close ends the session. The server answers with the
	// echoed close first, then the exit report, then its own
	// close — in that strict order.
	clientWrite(t, client, opClose, nil)
	if op, _ := clientRead(t, cr); op != opClose {
		t.Fatalf("frame 1 op = %d, want echoed close", op)
	}
	op, p := clientRead(t, cr)
	if op != opText || !strings.Contains(string(p), `"type":"exit"`) {
		t.Fatalf("frame 2 op=%d payload=%q, want exit frame", op, p)
	}
	if op, _ := clientRead(t, cr); op != opClose {
		t.Fatalf("frame 3 op = %d, want close", op)
	}
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Serve = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// TestServeExit runs a command that exits on its own: output, then
// the exit frame with the right code, then close.
func TestServeExit(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	ws := &Conn{conn: server, br: bufio.NewReader(server)}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- Serve(ws, Config{Cmd: []string{"sh", "-c", "echo out; exit 3"}})
	}()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	cr := bufio.NewReader(client)

	var gotOut, gotExit bool
	var code int
	for i := 0; i < 5 && !(gotOut && gotExit); i++ {
		op, p := clientRead(t, cr)
		switch op {
		case opBinary:
			if strings.Contains(string(p), "out") {
				gotOut = true
			}
		case opText:
			var msg struct {
				Type string `json:"type"`
				Code int    `json:"code"`
			}
			if json.Unmarshal(p, &msg) == nil && msg.Type == "exit" {
				gotExit, code = true, msg.Code
			}
		case opClose:
			i = 99 // stop after close
		}
	}
	if !gotOut {
		t.Fatal("missing shell output")
	}
	if !gotExit {
		t.Fatal("missing exit frame")
	}
	if code != 3 {
		t.Fatalf("code = %d, want 3", code)
	}
	// Drain the final close frame so the server's WriteClose can
	// complete (net.Pipe is unbuffered).
	if op, _ := clientRead(t, cr); op != opClose {
		t.Fatalf("op = %d, want close", op)
	}
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Serve = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// TestServeStartError ensures a bad command yields an error frame,
// not a hung session.
func TestServeStartError(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	ws := &Conn{conn: server, br: bufio.NewReader(server)}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- Serve(ws, Config{Cmd: []string{"/nonexistent-cmd-xyz"}})
	}()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	cr := bufio.NewReader(client)

	op, p := clientRead(t, cr)
	if op != opText || !strings.Contains(string(p), `"type":"error"`) {
		t.Fatalf("op=%d payload=%q, want error frame", op, p)
	}
	// Drain the final close frame (net.Pipe is unbuffered).
	if op, _ := clientRead(t, cr); op != opClose {
		t.Fatalf("op = %d, want close", op)
	}
	select {
	case err := <-serveErr:
		if err == nil {
			t.Fatal("Serve = nil, want error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// --- test client helpers (masked client → server frames) -------------

func clientWrite(t *testing.T, w io.Writer, opcode int, payload []byte) {
	t.Helper()
	clientWriteFrag(t, w, true, opcode, payload)
}

func clientWriteFrag(t *testing.T, w io.Writer, fin bool, opcode int, payload []byte) {
	t.Helper()
	var hdr []byte
	b0 := byte(opcode)
	if fin {
		b0 |= 0x80
	}
	hdr = append(hdr, b0)
	n := len(payload)
	const maskBit = 0x80
	switch {
	case n < 126:
		hdr = append(hdr, byte(n)|maskBit)
	case n < 65536:
		hdr = append(hdr, 126|maskBit, byte(n>>8), byte(n))
	default:
		t.Fatalf("payload too large for test helper: %d", n)
	}
	mask := [4]byte{0x11, 0x22, 0x33, 0x44}
	hdr = append(hdr, mask[:]...)
	if _, err := w.Write(hdr); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		return // no zero-byte write: it deadlocks net.Pipe
	}
	masked := make([]byte, n)
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := w.Write(masked); err != nil {
		t.Fatal(err)
	}
}

// clientRead reads one server→client frame (never masked).
func clientRead(t *testing.T, r *bufio.Reader) (int, []byte) {
	t.Helper()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		t.Fatal(err)
	}
	op := int(hdr[0] & 0x0F)
	if hdr[1]&0x80 != 0 {
		t.Fatal("server frame must not be masked")
	}
	n := int64(hdr[1] & 0x7F)
	switch n {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			t.Fatal(err)
		}
		n = int64(ext[0])<<8 | int64(ext[1])
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			t.Fatal(err)
		}
		n = int64(ext[4])<<24 | int64(ext[5])<<16 | int64(ext[6])<<8 | int64(ext[7])
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		t.Fatal(err)
	}
	return op, payload
}
