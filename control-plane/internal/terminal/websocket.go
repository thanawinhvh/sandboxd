// Package terminal serves one interactive shell per WebSocket
// connection inside a sandbox (`docker exec -it` on a PTY).
//
// Wire protocol (deliberately tiny so any xterm.js frontend can
// speak it):
//
//	Client → server:
//	  binary frame          stdin bytes, written to the shell as-is
//	  text frame            JSON control: {"type":"resize","cols":N,"rows":M}
//
//	Server → client:
//	  binary frame          shell output bytes, written to xterm as-is
//	  text frame            JSON control: {"type":"exit","code":N} once,
//	                        when the shell exits; {"type":"error",...} on
//	                        fatal session errors
//
// Ping frames are answered with pong automatically; a client close
// frame ends the session (the shell is killed). No subprotocols, no
// extensions, no dependencies — just RFC 6455 framing over a
// hijacked conn.
package terminal

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WebSocket frame opcodes (RFC 6455 §5.2, §11.8).
const (
	opCont   = 0x0
	opText   = 0x1
	opBinary = 0x2
	opClose  = 0x8
	opPing   = 0x9
	opPong   = 0xA
)

// wsGUID is the magic GUID every server accept-key derives from.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// maxMessageBytes caps one reassembled client message (a paste can
// be large, but an unbounded buffer is a memory-exhaustion hole).
const maxMessageBytes = 1 << 20 // 1 MiB

// writeTimeout bounds a single frame write so a dead peer cannot
// wedge the pty→ws pump forever.
const writeTimeout = 10 * time.Second

// ErrClosed is returned by ReadMessage after the close handshake.
var ErrClosed = errors.New("terminal: websocket closed")

// Conn is a minimal server-side WebSocket connection. Reads and
// writes are each safe for one goroutine plus Close from anywhere;
// concurrent writers are serialized by an internal mutex.
type Conn struct {
	conn net.Conn
	br   *bufio.Reader
	mu   sync.Mutex
}

// Accept validates the WebSocket handshake, hijacks the conn, and
// returns the framed connection. On failure it writes a plain HTTP
// error and returns nil.
func Accept(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if !headerHasToken(r.Header.Get("Connection"), "upgrade") ||
		!strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return nil, errors.New("terminal: not a websocket upgrade request")
	}
	if v := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Version")); v != "" && v != "13" {
		http.Error(w, "unsupported websocket version", http.StatusBadRequest)
		return nil, errors.New("terminal: unsupported websocket version")
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, errors.New("terminal: missing Sec-WebSocket-Key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket not supported", http.StatusInternalServerError)
		return nil, errors.New("terminal: response writer does not support hijack")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return nil, fmt.Errorf("terminal: hijack: %w", err)
	}
	// The 101 response goes through the hijacked bufio writer; the
	// reader side carries any bytes the client already pipelined.
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey(key) + "\r\n\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("terminal: write 101: %w", err)
	}
	if err := rw.Flush(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("terminal: flush 101: %w", err)
	}
	return &Conn{conn: conn, br: rw.Reader}, nil
}

// acceptKey derives the Sec-WebSocket-Accept value (RFC 6455 §1.3).
func acceptKey(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// headerHasToken reports whether a comma-separated header value
// contains tok (case-insensitive), e.g. Connection: keep-alive,
// Upgrade.
func headerHasToken(header, tok string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(part), tok) {
			return true
		}
	}
	return false
}

// Close closes the underlying conn. It unblocks a pending ReadMessage
// with an error.
func (c *Conn) Close() error { return c.conn.Close() }

// ReadMessage returns the next complete data message: opcode opText
// or opBinary plus its reassembled payload. Fragmented messages are
// reassembled; ping is answered with pong inline; a close frame is
// echoed and reported as ErrClosed.
func (c *Conn) ReadMessage() (opcode int, payload []byte, err error) {
	var msg []byte
	var msgOp int = -1
	for {
		fin, op, data, err := c.readFrame()
		if err != nil {
			return 0, nil, err
		}
		switch op {
		case opPing:
			_ = c.writeFrame(opPong, data) // best-effort keepalive reply
			continue
		case opPong:
			continue // unsolicited pong; nothing to do
		case opClose:
			_ = c.writeFrame(opClose, nil) // echo per RFC 6455 §5.5.1
			return 0, nil, ErrClosed
		case opText, opBinary:
			if msgOp != -1 {
				return 0, nil, errors.New("terminal: new message before previous finished")
			}
			msgOp, msg = op, data
		case opCont:
			if msgOp == -1 {
				return 0, nil, errors.New("terminal: stray continuation frame")
			}
			msg = append(msg, data...)
		default:
			return 0, nil, fmt.Errorf("terminal: unknown opcode %d", op)
		}
		if len(msg) > maxMessageBytes {
			return 0, nil, errors.New("terminal: message too large")
		}
		if fin {
			return msgOp, msg, nil
		}
	}
}

// readFrame reads one frame. Clients MUST mask (RFC 6455 §5.1); an
// unmasked client frame is a protocol error.
func (c *Conn) readFrame() (fin bool, opcode int, payload []byte, err error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c.br, hdr); err != nil {
		return false, 0, nil, err
	}
	fin = hdr[0]&0x80 != 0
	if hdr[0]&0x70 != 0 { // RSV1-3: no extensions negotiated
		return false, 0, nil, errors.New("terminal: unexpected RSV bits")
	}
	opcode = int(hdr[0] & 0x0F)
	masked := hdr[1]&0x80 != 0
	if !masked {
		return false, 0, nil, errors.New("terminal: client frame not masked")
	}
	n := int64(hdr[1] & 0x7F)
	switch n {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		n = int64(ext[0])<<8 | int64(ext[1])
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		n = int64(ext[0])<<56 | int64(ext[1])<<48 | int64(ext[2])<<40 | int64(ext[3])<<32 |
			int64(ext[4])<<24 | int64(ext[5])<<16 | int64(ext[6])<<8 | int64(ext[7])
		if n < 0 {
			return false, 0, nil, errors.New("terminal: negative frame length")
		}
	}
	if n > maxMessageBytes {
		return false, 0, nil, errors.New("terminal: frame too large")
	}
	var mask [4]byte
	if _, err := io.ReadFull(c.br, mask[:]); err != nil {
		return false, 0, nil, err
	}
	payload = make([]byte, n)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return false, 0, nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return fin, opcode, payload, nil
}

// WriteBinary sends payload as one binary frame (server→client
// frames are never masked).
func (c *Conn) WriteBinary(payload []byte) error { return c.writeFrame(opBinary, payload) }

// WriteText sends payload as one text frame.
func (c *Conn) WriteText(payload []byte) error { return c.writeFrame(opText, payload) }

// WriteClose sends a close frame (best-effort graceful shutdown;
// the caller still closes the conn).
func (c *Conn) WriteClose() error { return c.writeFrame(opClose, nil) }

func (c *Conn) writeFrame(opcode int, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	defer c.conn.SetWriteDeadline(time.Time{})
	var hdr []byte
	hdr = append(hdr, 0x80|byte(opcode)) // FIN, no RSV, no mask
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n < 65536:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 127, 0, 0, 0, 0,
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	if _, err := c.conn.Write(hdr); err != nil {
		return err
	}
	if n > 0 {
		if _, err := c.conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}
