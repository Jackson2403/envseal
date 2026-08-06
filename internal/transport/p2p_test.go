package transport

import (
	"bytes"
	"testing"
	"time"
)

func TestP2PRoundTrip(t *testing.T) {
	payload := []byte("DB_PASSWORD=super-secret\nAPI_KEY=abcd\n")
	addr, code, done, err := StartSender(0, func() ([]byte, error) {
		return payload, nil
	})
	if err != nil {
		t.Fatalf("start sender: %v", err)
	}

	got, err := Fetch(addr, code, 10*time.Second)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch\n got=%q\nwant=%q", got, payload)
	}
	if err := <-done; err != nil {
		t.Fatalf("sender reported error: %v", err)
	}
}

func TestP2PWrongCodeRejected(t *testing.T) {
	payload := []byte("A=1\n")
	addr, _, done, err := StartSender(0, func() ([]byte, error) { return payload, nil })
	if err != nil {
		t.Fatalf("start sender: %v", err)
	}

	// Fetch with the wrong code -> certificate pinning must fail.
	if _, err := Fetch(addr, "AAAA-BBBB-CCCC", 5*time.Second); err == nil {
		<-done // drain
		t.Fatal("expected an error when the pairing code is wrong")
	}
	<-done
}

func TestNewPairingCode(t *testing.T) {
	a, err := NewPairingCode()
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	b, _ := NewPairingCode()
	if a == "" || a == b {
		t.Fatalf("expected distinct non-empty codes, got %q and %q", a, b)
	}
	for _, r := range a {
		if (r < 'A' || r > 'Z') && (r < '2' || r > '9') && r != '-' {
			t.Fatalf("code contains unexpected char %q", r)
		}
	}
}
