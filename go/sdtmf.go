// Package sdtmf implements SDTMF v2 authenticated DTMF frames.
// See ../SPEC.md and ../test-vectors.json.
package sdtmf

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

const (
	Alphabet      = "0123456789ABCD"
	base          = 14
	DefaultCtrTx  = 2
	DefaultTagLen = 6
	DefaultStart  = "*"
	DefaultEnd    = "#"
	salt          = "SDTMF-v2"
	iters         = 100_000
)

var (
	ErrRejected = errors.New("sdtmf: frame rejected")
	errParams   = errors.New("sdtmf: ctr_tx must be 0..8 and tag_len 1..8")
	errMarker   = errors.New("sdtmf: marker must be empty or one character outside 0-9 A-D")
	errSameMark = errors.New("sdtmf: start and end must differ")
	errKeys     = errors.New("sdtmf: k_enc and k_mac must be 32 bytes")
	errMessage  = errors.New("sdtmf: message must be 1+ symbols from 0-9 A-D")
)

// Cipher is one end of an SDTMF conversation. Persist TxCtr and RxLast.
type Cipher struct {
	kEnc, kMac []byte
	ctrTx      int
	tagLen     int
	start      string
	end        string
	mod        uint32
	tagMod     uint32
	TxCtr      uint64
	RxLast     int64
}

type options struct {
	ctrTx, tagLen int
	start, end    string
}

// Option configures New / FromKeys.
type Option func(*options) error

func WithCtrTx(n int) Option {
	return func(o *options) error {
		if n < 0 || n > 8 {
			return errParams
		}
		o.ctrTx = n
		return nil
	}
}

func WithTagLen(n int) Option {
	return func(o *options) error {
		if n < 1 || n > 8 {
			return errParams
		}
		o.tagLen = n
		return nil
	}
}

func WithMarkers(start, end string) Option {
	return func(o *options) error {
		if err := checkMarker(start); err != nil {
			return err
		}
		if err := checkMarker(end); err != nil {
			return err
		}
		if start != "" && start == end {
			return errSameMark
		}
		o.start, o.end = start, end
		return nil
	}
}

func defaults() options {
	return options{ctrTx: DefaultCtrTx, tagLen: DefaultTagLen, start: DefaultStart, end: DefaultEnd}
}

func apply(opts []Option) (options, error) {
	o := defaults()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&o); err != nil {
			return o, err
		}
	}
	return o, nil
}

func checkMarker(m string) error {
	if len(m) > 1 || (m != "" && idx(m[0]) >= 0) {
		return errMarker
	}
	return nil
}

func idx(c byte) int {
	if c >= '0' && c <= '9' {
		return int(c - '0')
	}
	if c >= 'A' && c <= 'D' {
		return int(c-'A') + 10
	}
	return -1
}

func pow14(e int) uint32 {
	var r uint32 = 1
	for ; e > 0; e-- {
		r *= 14
	}
	return r
}

func toSym(n uint32, w int) string {
	if w == 0 {
		return ""
	}
	buf := make([]byte, w)
	for i := w - 1; i >= 0; i-- {
		buf[i] = Alphabet[n%base]
		n /= base
	}
	return string(buf)
}

func toInt(s string) uint32 {
	var n uint32
	for i := 0; i < len(s); i++ {
		n = n*base + uint32(idx(s[i]))
	}
	return n
}

func hmacSHA256(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

func pbkdf2(password, salt []byte, iter, dkLen int) []byte {
	nBlocks := (dkLen + sha256.Size - 1) / sha256.Size
	out := make([]byte, 0, nBlocks*sha256.Size)
	var block [4]byte
	for i := 1; i <= nBlocks; i++ {
		binary.BigEndian.PutUint32(block[:], uint32(i))
		u := hmacSHA256(password, append(salt, block[:]...))
		t := append([]byte(nil), u...)
		for j := 1; j < iter; j++ {
			u = hmacSHA256(password, u)
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:dkLen]
}

// DeriveKeys returns k_enc and k_mac for a UTF-8 password.
func DeriveKeys(password string) (kEnc, kMac []byte) {
	master := pbkdf2([]byte(password), []byte(salt), iters, 32)
	kEnc = hmacSHA256(master, []byte("enc"))
	kMac = hmacSHA256(master, []byte("mac"))
	return
}

func newCipher(kEnc, kMac []byte, o options) (*Cipher, error) {
	if len(kEnc) != 32 || len(kMac) != 32 {
		return nil, errKeys
	}
	enc := make([]byte, 32)
	mac := make([]byte, 32)
	copy(enc, kEnc)
	copy(mac, kMac)
	return &Cipher{
		kEnc: enc, kMac: mac,
		ctrTx: o.ctrTx, tagLen: o.tagLen,
		start: o.start, end: o.end,
		mod: pow14(o.ctrTx), tagMod: pow14(o.tagLen),
		RxLast: -1,
	}, nil
}

func New(password string, opts ...Option) (*Cipher, error) {
	o, err := apply(opts)
	if err != nil {
		return nil, err
	}
	kEnc, kMac := DeriveKeys(password)
	return newCipher(kEnc, kMac, o)
}

func FromKeys(kEnc, kMac []byte, opts ...Option) (*Cipher, error) {
	o, err := apply(opts)
	if err != nil {
		return nil, err
	}
	return newCipher(kEnc, kMac, o)
}

func (c *Cipher) FrameLen(msgLen int) int {
	return len(c.start) + c.ctrTx + msgLen + c.tagLen + len(c.end)
}

func (c *Cipher) State() (txCtr uint64, rxLast int64) {
	return c.TxCtr, c.RxLast
}

func (c *Cipher) SetState(txCtr uint64, rxLast int64) {
	c.TxCtr, c.RxLast = txCtr, rxLast
}

func (c *Cipher) keystream(ctr uint64, n int) []byte {
	out := make([]byte, 0, n)
	var msg [10]byte
	binary.BigEndian.PutUint64(msg[:8], ctr)
	for blk := uint16(0); len(out) < n; blk++ {
		binary.BigEndian.PutUint16(msg[8:], blk)
		d := hmacSHA256(c.kEnc, msg[:])
		for _, b := range d {
			if b < 252 {
				out = append(out, b%base)
				if len(out) == n {
					break
				}
			}
		}
	}
	return out
}

func (c *Cipher) tag(ctr uint64, ct string) string {
	buf := make([]byte, 8+len(ct))
	binary.BigEndian.PutUint64(buf[:8], ctr)
	copy(buf[8:], ct)
	d := hmacSHA256(c.kMac, buf)
	var r uint32
	m := c.tagMod
	for _, b := range d {
		r = uint32((uint64(r)*256 + uint64(b)) % uint64(m))
	}
	return toSym(r, c.tagLen)
}

func validMsg(msg string) bool {
	if msg == "" {
		return false
	}
	for i := 0; i < len(msg); i++ {
		if idx(msg[i]) < 0 {
			return false
		}
	}
	return true
}

func (c *Cipher) Encrypt(msg string) (string, error) {
	if !validMsg(msg) {
		return "", errMessage
	}
	c.TxCtr++
	ctr := c.TxCtr
	ks := c.keystream(ctr, len(msg))
	ct := make([]byte, len(msg))
	for i := 0; i < len(msg); i++ {
		ct[i] = Alphabet[(idx(msg[i])+int(ks[i]))%base]
	}
	cts := string(ct)
	return c.start + toSym(uint32(ctr%uint64(c.mod)), c.ctrTx) + cts + c.tag(ctr, cts) + c.end, nil
}

func (c *Cipher) Decrypt(frame string) (string, error) {
	ls, le := len(c.start), len(c.end)
	if len(frame) < ls+le ||
		(ls > 0 && frame[:ls] != c.start) ||
		(le > 0 && frame[len(frame)-le:] != c.end) {
		return "", ErrRejected
	}
	s := frame[ls : len(frame)-le]
	if len(s) <= c.ctrTx+c.tagLen {
		return "", ErrRejected
	}
	for i := 0; i < len(s); i++ {
		if idx(s[i]) < 0 {
			return "", ErrRejected
		}
	}
	low := toInt(s[:c.ctrTx])
	ct := s[c.ctrTx : len(s)-c.tagLen]
	got := s[len(s)-c.tagLen:]
	baseCtr := c.RxLast + 1
	if baseCtr < 1 {
		baseCtr = 1
	}
	mod := int64(c.mod)
	rem := (int64(low) - baseCtr) % mod
	if rem < 0 {
		rem += mod
	}
	ctr := uint64(baseCtr + rem)
	want := c.tag(ctr, ct)
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return "", ErrRejected
	}
	c.RxLast = int64(ctr)
	ks := c.keystream(ctr, len(ct))
	plain := make([]byte, len(ct))
	for i := 0; i < len(ct); i++ {
		v := idx(ct[i]) - int(ks[i])
		if v < 0 {
			v += base
		}
		plain[i] = Alphabet[v]
	}
	return string(plain), nil
}

// used by tests
func (c *Cipher) debugKS(ctr uint64, n int) []int {
	ks := c.keystream(ctr, n)
	out := make([]int, n)
	for i, b := range ks {
		out[i] = int(b)
	}
	return out
}

func (c *Cipher) debugParams() (ctrTx, tagLen int, start, end string) {
	return c.ctrTx, c.tagLen, c.start, c.end
}
