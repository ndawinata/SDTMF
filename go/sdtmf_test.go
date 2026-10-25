package sdtmf

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type vectors struct {
	Password string `json:"password"`
	KEnc     string `json:"k_enc"`
	KMac     string `json:"k_mac"`
	Defaults struct {
		CtrTx  int    `json:"ctr_tx"`
		TagLen int    `json:"tag_len"`
		Start  string `json:"start"`
		End    string `json:"end"`
	} `json:"defaults"`
	Keystream struct {
		Ctr1 []int `json:"ctr1_len10"`
		Ctr2 []int `json:"ctr2_len10"`
		Ctr3 []int `json:"ctr3_len16"`
	} `json:"keystream"`
	Encrypt []struct {
		Ctr   uint64 `json:"ctr"`
		Msg   string `json:"msg"`
		Frame string `json:"frame"`
	} `json:"encrypt"`
	DecryptOK []struct {
		StartRxLast int64  `json:"start_rx_last"`
		Frame       string `json:"frame"`
		Msg         string `json:"msg"`
		EndRxLast   int64  `json:"end_rx_last"`
	} `json:"decrypt_ok"`
	DecryptReject []struct {
		Reason      string `json:"reason"`
		StartRxLast int64  `json:"start_rx_last"`
		Frame       string `json:"frame"`
	} `json:"decrypt_reject"`
	WrongPassword            string `json:"wrong_password"`
	WrongPasswordRejectFrame string `json:"wrong_password_reject_frame"`
	CounterWrap              struct {
		StartTxCtr  uint64 `json:"start_tx_ctr"`
		Msg         string `json:"msg"`
		Frame       string `json:"frame"`
		EndTxCtr    uint64 `json:"end_tx_ctr"`
		StartRxLast int64  `json:"start_rx_last"`
		EndRxLast   int64  `json:"end_rx_last"`
	} `json:"counter_wrap"`
	Configs []struct {
		CtrTx  int    `json:"ctr_tx"`
		TagLen int    `json:"tag_len"`
		Start  string `json:"start"`
		End    string `json:"end"`
		Msg    string `json:"msg"`
		Frame  string `json:"frame"`
		Frame2 string `json:"frame2"`
	} `json:"configs"`
	ConfigReject []struct {
		Reason string `json:"reason"`
		CtrTx  int    `json:"ctr_tx"`
		TagLen int    `json:"tag_len"`
		Start  string `json:"start"`
		End    string `json:"end"`
		Frame  string `json:"frame"`
	} `json:"config_reject"`
	InvalidConfigs []struct {
		Reason string `json:"reason"`
		CtrTx  int    `json:"ctr_tx"`
		TagLen int    `json:"tag_len"`
		Start  string `json:"start"`
		End    string `json:"end"`
	} `json:"invalid_configs"`
}

func load(t *testing.T) vectors {
	t.Helper()
	p := filepath.Join("..", "test-vectors.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func cfg(t *testing.T, pw string, ctrTx, tagLen int, start, end string) *Cipher {
	t.Helper()
	c, err := New(pw, WithCtrTx(ctrTx), WithTagLen(tagLen), WithMarkers(start, end))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestOfficialVectors(t *testing.T) {
	v := load(t)
	kEnc, kMac := DeriveKeys(v.Password)
	if hex.EncodeToString(kEnc) != v.KEnc {
		t.Fatalf("k_enc\n got %s\n exp %s", hex.EncodeToString(kEnc), v.KEnc)
	}
	if hex.EncodeToString(kMac) != v.KMac {
		t.Fatalf("k_mac\n got %s\n exp %s", hex.EncodeToString(kMac), v.KMac)
	}

	c, err := New(v.Password)
	if err != nil {
		t.Fatal(err)
	}
	ct, tl, st, en := c.debugParams()
	if ct != v.Defaults.CtrTx || tl != v.Defaults.TagLen || st != v.Defaults.Start || en != v.Defaults.End {
		t.Fatalf("defaults %d %d %q %q", ct, tl, st, en)
	}
	eqSlice(t, "KS(1,10)", c.debugKS(1, 10), v.Keystream.Ctr1)
	eqSlice(t, "KS(2,10)", c.debugKS(2, 10), v.Keystream.Ctr2)
	eqSlice(t, "KS(3,16)", c.debugKS(3, 16), v.Keystream.Ctr3)

	tx, _ := New(v.Password)
	for _, row := range v.Encrypt {
		got, err := tx.Encrypt(row.Msg)
		if err != nil {
			t.Fatal(err)
		}
		if got != row.Frame {
			t.Fatalf("encrypt(%q)\n got %s\n exp %s", row.Msg, got, row.Frame)
		}
		if tx.TxCtr != row.Ctr {
			t.Fatalf("tx_ctr after %q: %d", row.Msg, tx.TxCtr)
		}
	}

	raw, err := FromKeys(kEnc, kMac)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := raw.Encrypt(v.Encrypt[0].Msg)
	if got != v.Encrypt[0].Frame {
		t.Fatalf("from_keys %s", got)
	}

	rx, _ := New(v.Password)
	for _, row := range v.DecryptOK {
		rx.RxLast = row.StartRxLast
		msg, err := rx.Decrypt(row.Frame)
		if err != nil || msg != row.Msg {
			t.Fatalf("decrypt %s -> %q %v", row.Frame, msg, err)
		}
		if rx.RxLast != row.EndRxLast {
			t.Fatalf("rx_last after %s: %d", row.Frame, rx.RxLast)
		}
	}

	for _, row := range v.DecryptReject {
		rx, _ = New(v.Password)
		rx.RxLast = row.StartRxLast
		if _, err := rx.Decrypt(row.Frame); err != ErrRejected {
			t.Fatalf("reject %s: %v", row.Reason, err)
		}
		if rx.RxLast != row.StartRxLast {
			t.Fatalf("rx_last changed (%s)", row.Reason)
		}
	}

	wrong, _ := New(v.WrongPassword)
	if _, err := wrong.Decrypt(v.WrongPasswordRejectFrame); err != ErrRejected {
		t.Fatal("wrong password accepted")
	}

	w := v.CounterWrap
	tx, _ = New(v.Password)
	tx.TxCtr = w.StartTxCtr
	got, _ = tx.Encrypt(w.Msg)
	if got != w.Frame || tx.TxCtr != w.EndTxCtr {
		t.Fatalf("wrap encrypt %s ctr=%d", got, tx.TxCtr)
	}
	rx, _ = New(v.Password)
	rx.RxLast = w.StartRxLast
	msg, err := rx.Decrypt(w.Frame)
	if err != nil || msg != w.Msg || rx.RxLast != w.EndRxLast {
		t.Fatalf("wrap decrypt %q %v %d", msg, err, rx.RxLast)
	}

	for _, row := range v.Configs {
		tx = cfg(t, v.Password, row.CtrTx, row.TagLen, row.Start, row.End)
		f1, err := tx.Encrypt(row.Msg)
		if err != nil || f1 != row.Frame {
			t.Fatalf("config frame %v: %s", row, f1)
		}
		f2, err := tx.Encrypt(row.Msg)
		if err != nil || f2 != row.Frame2 {
			t.Fatalf("config frame2 %s", f2)
		}
		if tx.FrameLen(len(row.Msg)) != len(row.Frame) {
			t.Fatalf("frame_len %d", tx.FrameLen(len(row.Msg)))
		}
		rx = cfg(t, v.Password, row.CtrTx, row.TagLen, row.Start, row.End)
		if m, err := rx.Decrypt(row.Frame); err != nil || m != row.Msg {
			t.Fatalf("config decrypt %v", err)
		}
		if m, err := rx.Decrypt(row.Frame2); err != nil || m != row.Msg {
			t.Fatalf("config decrypt2 %v", err)
		}
		if _, err := rx.Decrypt(row.Frame); err != ErrRejected {
			t.Fatal("config replay")
		}
	}

	for _, row := range v.ConfigReject {
		c := cfg(t, v.Password, row.CtrTx, row.TagLen, row.Start, row.End)
		if _, err := c.Decrypt(row.Frame); err != ErrRejected {
			t.Fatalf("config reject %s", row.Reason)
		}
	}

	for _, row := range v.InvalidConfigs {
		_, err := New(v.Password, WithCtrTx(row.CtrTx), WithTagLen(row.TagLen), WithMarkers(row.Start, row.End))
		if err == nil {
			t.Fatalf("invalid config accepted: %s", row.Reason)
		}
	}
}

func eqSlice(t *testing.T, label string, got, exp []int) {
	t.Helper()
	if len(got) != len(exp) {
		t.Fatalf("%s len %d != %d", label, len(got), len(exp))
	}
	for i := range got {
		if got[i] != exp[i] {
			t.Fatalf("%s %v != %v", label, got, exp)
		}
	}
}
