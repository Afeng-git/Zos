package main

import (
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"hash/crc32"
	"net"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	magic          = "ZOSMC101"
	kindData       = 1
	kindWindowEnd  = 2
	kindSessionEnd = 3
	kindAck        = 4
	kindNack       = 5
	kindHello      = 6
	kindComplete   = 7
	kindError      = 8
	kindBeacon     = 9
	headerSize     = 31
	payloadSize    = 1200
)

type packet struct {
	kind       byte
	window     uint32
	seq, total uint16
	payload    []byte
}

func sessionTag(id string) [8]byte {
	h := sha256.Sum256([]byte(id))
	var t [8]byte
	copy(t[:], h[:8])
	return t
}
func groupFor(id string) string {
	h := sha256.Sum256([]byte(id))
	return fmt.Sprintf("239.193.%d.%d", 1+int(h[0])%253, 1+int(h[1])%253)
}
func parseMAC(s string) ([6]byte, error) {
	var m [6]byte
	hw, e := net.ParseMAC(strings.ReplaceAll(strings.TrimSpace(s), "-", ":"))
	if e != nil || len(hw) != 6 {
		return m, fmt.Errorf("invalid MAC %q", s)
	}
	copy(m[:], hw)
	return m, nil
}
func pack(tag [8]byte, kind byte, window uint32, seq, total uint16, payload []byte) []byte {
	b := make([]byte, headerSize+len(payload))
	copy(b[:8], []byte(magic))
	copy(b[8:16], tag[:])
	b[16] = kind
	binary.BigEndian.PutUint32(b[17:21], window)
	binary.BigEndian.PutUint16(b[21:23], seq)
	binary.BigEndian.PutUint16(b[23:25], total)
	binary.BigEndian.PutUint16(b[25:27], uint16(len(payload)))
	binary.BigEndian.PutUint32(b[27:31], crc32.ChecksumIEEE(payload))
	copy(b[31:], payload)
	return b
}
func unpack(b []byte, tag [8]byte) (*packet, bool) {
	if len(b) < headerSize || string(b[:8]) != magic || string(b[8:16]) != string(tag[:]) {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(b[25:27]))
	if n != len(b)-headerSize {
		return nil, false
	}
	p := b[31:]
	if crc32.ChecksumIEEE(p) != binary.BigEndian.Uint32(b[27:31]) {
		return nil, false
	}
	return &packet{b[16], binary.BigEndian.Uint32(b[17:21]), binary.BigEndian.Uint16(b[21:23]), binary.BigEndian.Uint16(b[23:25]), append([]byte(nil), p...)}, true
}
func macKey(m [6]byte) string { return string(m[:]) }
func profile(name string) (int, time.Duration, time.Duration) {
	switch name {
	case "compatible":
		return 64, time.Millisecond, 800 * time.Millisecond
	case "maximum":
		return 160, 0, 250 * time.Millisecond
	default:
		return 128, 0, 350 * time.Millisecond
	}
}
func main() {
	file := flag.String("file", "", "compressed image file")
	iface := flag.String("interface", "", "server IPv4")
	port := flag.Int("portbase", 0, "data port")
	session := flag.String("session-id", "", "ZOS session id")
	macList := flag.String("expected-macs", "", "comma separated receiver MACs")
	prof := flag.String("profile", "gigabit", "compatible|gigabit|maximum")
	timeout := flag.Int("start-timeout", 900, "receiver wait timeout")
	version := flag.Bool("version", false, "show version")
	flag.Parse()
	if *version {
		fmt.Println("Jingyun ZOSMC udp-sender 1.0")
		return
	}
	if *file == "" || *iface == "" || *port < 1024 || *session == "" || *macList == "" {
		fmt.Fprintln(os.Stderr, "required: --file --interface --portbase --session-id --expected-macs")
		os.Exit(2)
	}
	serverIP := net.ParseIP(*iface).To4()
	if serverIP == nil {
		fmt.Fprintln(os.Stderr, "invalid IPv4")
		os.Exit(2)
	}
	expected := map[string][6]byte{}
	for _, s := range strings.Split(*macList, ",") {
		m, e := parseMAC(s)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(2)
		}
		expected[macKey(m)] = m
	}
	if len(expected) == 0 {
		fmt.Fprintln(os.Stderr, "no receivers")
		os.Exit(2)
	}
	f, e := os.Open(*file)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	tag := sessionTag(*session)
	group := &net.UDPAddr{IP: net.ParseIP(groupFor(*session)).To4(), Port: *port}
	data, e := net.ListenUDP("udp4", &net.UDPAddr{IP: serverIP, Port: 0})
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(3)
	}
	defer data.Close()
	_ = data.SetWriteBuffer(4 * 1024 * 1024)
	raw, e := data.SyscallConn()
	if e == nil {
		_ = raw.Control(func(fd uintptr) {
			var a [4]byte
			copy(a[:], serverIP)
			_ = syscall.SetsockoptInet4Addr(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, a)
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, 1)
		})
	}
	ctrl, e := net.ListenUDP("udp4", &net.UDPAddr{IP: serverIP, Port: *port + 1})
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(3)
	}
	defer ctrl.Close()
	_ = ctrl.SetReadBuffer(4 * 1024 * 1024)
	send := func(b []byte) { _, _ = data.WriteToUDP(b, group) }
	recvUntil := func(deadline time.Time) (*packet, bool) {
		buf := make([]byte, 65535)
		for time.Now().Before(deadline) {
			_ = ctrl.SetReadDeadline(deadline)
			n, _, er := ctrl.ReadFromUDP(buf)
			if er != nil {
				return nil, false
			}
			if p, ok := unpack(buf[:n], tag); ok {
				return p, true
			}
		}
		return nil, false
	}
	connected := map[string]bool{}
	deadline := time.Now().Add(time.Duration(*timeout) * time.Second)
	beacon := pack(tag, kindBeacon, 0, 0, 0, nil)
	for len(connected) < len(expected) {
		if time.Now().After(deadline) {
			fmt.Fprintf(os.Stderr, "timeout waiting receivers %d/%d\n", len(connected), len(expected))
			os.Exit(4)
		}
		send(beacon)
		if p, ok := recvUntil(time.Now().Add(500 * time.Millisecond)); ok && p.kind == kindHello && len(p.payload) >= 6 {
			var m [6]byte
			copy(m[:], p.payload[:6])
			if _, yes := expected[macKey(m)]; yes {
				connected[macKey(m)] = true
			}
		}
		fmt.Fprintf(os.Stderr, "receivers %d/%d\r", len(connected), len(expected))
	}
	fmt.Fprintln(os.Stderr, "\nall receivers connected")
	count, pacing, wait := profile(*prof)
	window := uint32(0)
	digest := sha256.New()
	buf := make([]byte, payloadSize)
	for {
		packets := make([][]byte, 0, count)
		for i := 0; i < count; i++ {
			n, er := f.Read(buf)
			if n > 0 {
				b := append([]byte(nil), buf[:n]...)
				packets = append(packets, b)
				_, _ = digest.Write(b)
			}
			if er != nil {
				break
			}
		}
		if len(packets) == 0 {
			break
		}
		acked := map[string]bool{}
		missing := map[int]bool{}
		for i := range packets {
			missing[i] = true
		}
		windowDeadline := time.Now().Add(180 * time.Second)
		for len(acked) < len(expected) {
			if time.Now().After(windowDeadline) {
				fmt.Fprintln(os.Stderr, "window timeout")
				os.Exit(5)
			}
			idx := make([]int, 0, len(missing))
			for i := range missing {
				idx = append(idx, i)
			}
			sort.Ints(idx)
			for _, i := range idx {
				send(pack(tag, kindData, window, uint16(i), uint16(len(packets)), packets[i]))
				if pacing > 0 && (i+1)%32 == 0 {
					time.Sleep(pacing)
				}
			}
			end := pack(tag, kindWindowEnd, window, 0, uint16(len(packets)), nil)
			send(end)
			send(end)
			requested := map[int]bool{}
			rd := time.Now().Add(wait)
			for time.Now().Before(rd) {
				p, ok := recvUntil(rd)
				if !ok {
					break
				}
				if p.window != window || len(p.payload) < 6 {
					continue
				}
				var m [6]byte
				copy(m[:], p.payload[:6])
				key := macKey(m)
				if _, yes := expected[key]; !yes {
					continue
				}
				if p.kind == kindAck {
					acked[key] = true
				} else if p.kind == kindNack && !acked[key] {
					body := p.payload[6:]
					for i := 0; i+1 < len(body); i += 2 {
						requested[int(binary.BigEndian.Uint16(body[i:i+2]))] = true
					}
				} else if p.kind == kindError {
					fmt.Fprintln(os.Stderr, string(p.payload[6:]))
					os.Exit(5)
				}
			}
			if len(acked) < len(expected) {
				if len(requested) > 0 {
					missing = requested
				} else {
					missing = map[int]bool{}
					for i := range packets {
						missing[i] = true
					}
				}
			}
		}
		window++
	}
	sum := digest.Sum(nil)
	meta := make([]byte, 40)
	binary.BigEndian.PutUint64(meta[:8], uint64(st.Size()))
	copy(meta[8:], sum)
	end := pack(tag, kindSessionEnd, window, 0, 0, meta)
	done := map[string]bool{}
	deadline = time.Now().Add(120 * time.Second)
	for len(done) < len(expected) {
		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, "final verification timeout")
			os.Exit(6)
		}
		send(end)
		send(end)
		send(end)
		rd := time.Now().Add(800 * time.Millisecond)
		for time.Now().Before(rd) {
			p, ok := recvUntil(rd)
			if !ok {
				break
			}
			if len(p.payload) < 6 {
				continue
			}
			var m [6]byte
			copy(m[:], p.payload[:6])
			key := macKey(m)
			if _, yes := expected[key]; !yes {
				continue
			}
			if p.kind == kindComplete {
				done[key] = true
			} else if p.kind == kindError {
				fmt.Fprintln(os.Stderr, string(p.payload[6:]))
				os.Exit(6)
			}
		}
	}
	fmt.Fprintln(os.Stderr, "multicast complete")
}
