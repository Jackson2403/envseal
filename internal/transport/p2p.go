package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"
)

// P2P pairs two EnvSync instances over a direct encrypted TCP connection.
// A human-readable pairing code seeds a deterministic Ed25519 certificate, so
// the receiver can cryptographically verify (pin) the sender's identity from
// the code alone — a man-in-the-middle needs to know the code to impersonate.
// The transported payload is the same Envelope used for the file transport.

const pairingAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ" // no 0/O/1/I/L

// NewPairingCode returns a fresh human-friendly pairing code.
func NewPairingCode() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Map onto the unambiguous alphabet to avoid/skip confusing chars.
	var sb strings.Builder
	for _, n := range b {
		sb.WriteByte(pairingAlphabet[int(n)%len(pairingAlphabet)])
	}
	code := sb.String()
	return groupCode(code), nil
}

func groupCode(code string) string {
	var b strings.Builder
	for i, c := range code {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(c)
	}
	return b.String()
}

func normalizeCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(code, "-", ""))
}

// codeKeyPair derives the deterministic certificate + ed25519 keypair for a
// pairing code and returns a tls.Certificate plus the expected public key.
func codeKeyPair(code string) (tls.Certificate, ed25519.PublicKey, error) {
	seed := sha256.Sum256([]byte(normalizeCode(code)))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return tls.Certificate{}, nil, fmt.Errorf("derived key is not ed25519")
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"envsync"},
	}
	derCert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	derKey, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derKey})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return cert, pub, nil
}

// verifyPinned returns a VerifyPeerCertificate callback that enforces the
// peer's TLS certificate is the one derived from the pairing code.
func verifyPinned(want ed25519.PublicKey) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no peer certificate presented")
		}
		c, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse peer certificate: %w", err)
		}
		got, ok := c.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("peer certificate is not ed25519")
		}
		if !strings.EqualFold(fmt.Sprintf("%x", got), fmt.Sprintf("%x", want)) {
			return fmt.Errorf("peer certificate does not match the pairing code")
		}
		return nil
	}
}

// lanIPv4 best-effort returns the machine's primary LAN IPv4 address, falling
// back to loopback. Used so the advertised P2P address is actually dialable.
func lanIPv4() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return "127.0.0.1"
	}
	return host
}

// StartSender opens an encrypted listener, seeds it with a fresh pairing code,
// and serves one payload produced by `provide`. It returns the address clients
// should dial, the pairing code, and a channel that reports the serve result.
func StartSender(port int, provide func() ([]byte, error)) (addr, code string, done <-chan error, err error) {
	code, err = NewPairingCode()
	if err != nil {
		return "", "", nil, err
	}
	cert, _, err := codeKeyPair(code)
	if err != nil {
		return "", "", nil, err
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return "", "", nil, fmt.Errorf("listen: %w", err)
	}
	listenHost, listenPort, _ := net.SplitHostPort(ln.Addr().String())
	_ = listenHost
	advertisedPort := port
	if port == 0 {
		advertisedPort, _ = strconv.Atoi(listenPort)
	}
	addr = net.JoinHostPort(lanIPv4(), strconv.Itoa(advertisedPort))

	tlsLn := tls.NewListener(ln, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	})

	ch := make(chan error, 1)
	go func() {
		defer close(ch)
		conn, aerr := tlsLn.Accept()
		if aerr != nil {
			ch <- fmt.Errorf("accept: %w", aerr)
			return
		}
		defer conn.Close()
		defer tlsLn.Close()
		_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
		data, perr := provide()
		if perr != nil {
			ch <- perr
			return
		}
		if _, werr := conn.Write(data); werr != nil {
			ch <- werr
			return
		}
		ch <- nil
	}()
	return addr, code, ch, nil
}

// Fetch dials a sender, verifies its certificate against the pairing code,
// and reads the payload.
func Fetch(addr, code string, timeout time.Duration) ([]byte, error) {
	_, want, err := codeKeyPair(code)
	if err != nil {
		return nil, err
	}
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		MinVersion:            tls.VersionTLS13,
		InsecureSkipVerify:    true, // verified manually below
		VerifyPeerCertificate: verifyPinned(want),
		ServerName:            "envsync",
	})
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return io.ReadAll(conn)
}
