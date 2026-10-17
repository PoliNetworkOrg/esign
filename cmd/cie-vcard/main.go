// Command cie-vcard serves the CIE simulator (internal/token/cie/cardsim) as a virtual smart card to the vpcd
// driver of vsmartcard (https://github.com/frankmorgner/vsmartcard), so that pcsc-lite, and every PC/SC program
// above it, sees a CIE on a reader. It is a test tool for scripts/interop; it never touches a real card.
//
// The vpcd protocol is a TCP stream of messages, each a two-byte big-endian length and a payload. A one-byte
// payload is a control message from vpcd: 0 power off, 1 power on, 2 reset, 4 ATR request (answered with the ATR).
// Any other payload is a command APDU, answered with the response APDU.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/PoliNetworkOrg/sign-agent/internal/token/cie/cardsim"
)

func main() {
	addr := flag.String("vpcd", "127.0.0.1:35963", "address of vpcd")
	control := flag.String("control", "127.0.0.1:35999", "address of the HTTP control endpoint (empty to disable)")
	pin := flag.String("pin", "12345678", "card PIN")
	variant := flag.String("variant", "nxp", "chip family: nxp, gemalto or unlisted")
	certOut := flag.String("cert-out", "", "write the citizen and issuer certificates (PEM) to this file")
	trace := flag.Bool("trace", false, "log every APDU")
	flag.Parse()

	opts := cardsim.Options{PIN: *pin}
	switch *variant {
	case "nxp":
	case "gemalto":
		opts.Variant = cardsim.Gemalto
	case "unlisted":
		opts.Variant = cardsim.Unlisted
	default:
		log.Fatalf("unknown variant %q", *variant)
	}
	card, err := cardsim.New(opts)
	if err != nil {
		log.Fatal(err)
	}
	if *certOut != "" {
		var out []byte
		for _, c := range [][]byte{card.Certificate().Raw, card.IssuerCertificate().Raw} {
			out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
		}
		if err := os.WriteFile(*certOut, out, 0o644); err != nil {
			log.Fatal(err)
		}
	}
	v := &vcard{card: card, addr: *addr, trace: *trace, present: true}
	log.Printf("%s, ATR %X", card.Describe(), card.ATR())
	if *control != "" {
		go func() { log.Fatal(http.ListenAndServe(*control, v.handler())) }()
	}
	v.run()
}

type vcard struct {
	card  *cardsim.Card
	addr  string
	trace bool

	mu        sync.Mutex
	present   bool
	removedAt time.Time
	conn      net.Conn
}

// minAbsence keeps a removed card away long enough for pcscd's presence polling to see the removal; a quicker
// reconnection looks to pcscd like a card that never left but stopped answering.
const minAbsence = 2 * time.Second

// run keeps the card connected to vpcd while it is "inserted": vpcd reports a card on its reader exactly while a
// client is connected.
func (v *vcard) run() {
	for {
		v.mu.Lock()
		present := v.present && time.Since(v.removedAt) >= minAbsence
		v.mu.Unlock()
		if !present {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		conn, err := net.Dial("tcp", v.addr)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		v.mu.Lock()
		v.conn = conn
		v.mu.Unlock()
		log.Printf("card inserted (connected to vpcd at %s)", v.addr)
		err = v.serve(conn)
		_ = conn.Close()
		v.card.Reset()
		log.Printf("card removed: %v", err)
	}
}

func (v *vcard) serve(conn net.Conn) error {
	var size [2]byte
	for {
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return err
		}
		msg := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, msg); err != nil {
			return err
		}
		var reply []byte
		switch {
		case len(msg) == 1 && msg[0] == 4:
			reply = v.card.ATR()
		case len(msg) == 1:
			// Power off, power on and reset all leave the card in its initial state.
			v.card.Reset()
			continue
		default:
			resp, err := v.card.Transmit(msg)
			if err != nil {
				return err
			}
			if v.trace {
				log.Printf("> %X\n< %X", msg, resp)
			}
			reply = resp
		}
		out := binary.BigEndian.AppendUint16(nil, uint16(len(reply)))
		if _, err := conn.Write(append(out, reply...)); err != nil {
			return err
		}
	}
}

func (v *vcard) setPresent(present bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.present = present
	if !present {
		v.removedAt = time.Now()
	}
	if !present && v.conn != nil {
		_ = v.conn.Close()
		v.conn = nil
	}
}

// handler is the control endpoint the harness scripts use: POST /remove and /insert move the card, GET /status
// reports the counters, GET /certificate returns the citizen certificate in PEM.
func (v *vcard) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /remove", func(w http.ResponseWriter, r *http.Request) { v.setPresent(false) })
	mux.HandleFunc("POST /insert", func(w http.ResponseWriter, r *http.Request) { v.setPresent(true) })
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		transmits, resets := v.card.Stats()
		v.mu.Lock()
		present := v.present
		v.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"present": present, "pinTriesLeft": v.card.PINTriesLeft(), "transmits": transmits, "resets": resets,
			"atr": hex.EncodeToString(v.card.ATR()),
		})
	})
	mux.HandleFunc("GET /certificate", func(w http.ResponseWriter, r *http.Request) {
		_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: v.card.Certificate().Raw})
	})
	return mux
}
