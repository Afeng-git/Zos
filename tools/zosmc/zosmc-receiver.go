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
	hw, e := net.ParseMAC(strings.ReplaceAll(s, "-", ":"))
	if e != nil || len(hw) != 6 {
		return m, fmt.Errorf("invalid MAC %q", s)
	}
	copy(m[:], hw)
	return m, nil
}
func pack(tag [8]byte, kind byte, window uint32, seq, total uint16, payload []byte) []byte {
	b := make([]byte, headerSize+len(payload))
	copy(b[0:8], []byte(magic))
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
func unpack(buf []byte, tag [8]byte) (*packet, bool) {
	if len(buf) < headerSize || string(buf[0:8]) != magic || string(buf[8:16]) != string(tag[:]) {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(buf[25:27]))
	if n != len(buf)-headerSize {
		return nil, false
	}
	p := buf[31:]
	if crc32.ChecksumIEEE(p) != binary.BigEndian.Uint32(buf[27:31]) {
		return nil, false
	}
	cp := append([]byte(nil), p...)
	return &packet{buf[16], binary.BigEndian.Uint32(buf[17:21]), binary.BigEndian.Uint16(buf[21:23]), binary.BigEndian.Uint16(buf[23:25]), cp}, true
}
func ifaceByIP(ip net.IP) (*net.Interface, error) {
	ifs, e := net.Interfaces()
	if e != nil {
		return nil, e
	}
	for i := range ifs {
		as, _ := ifs[i].Addrs()
		for _, a := range as {
			var x net.IP
			switch v := a.(type) {
			case *net.IPNet:
				x = v.IP
			case *net.IPAddr:
				x = v.IP
			}
			if x != nil && x.Equal(ip) {
				return &ifs[i], nil
			}
		}
	}
	return nil, fmt.Errorf("no interface owns %s", ip)
}

func main() {
	session := flag.String("session-id", "", "ZOS multicast session id")
	server := flag.String("server-ip", "", "manager IPv4")
	local := flag.String("interface-ip", "", "client IPv4 used for multicast membership")
	port := flag.Int("port", 0, "multicast data port")
	macs := flag.String("mac", "", "client MAC")
	timeout := flag.Int("receive-timeout", 180, "receive timeout seconds")
	flag.Parse()
	if *session == "" || *server == "" || *local == "" || *port < 1024 || *macs == "" {
		fmt.Fprintln(os.Stderr, "missing required ZOS multicast parameters")
		os.Exit(2)
	}
	client, e := parseMAC(*macs)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	localIP := net.ParseIP(*local).To4()
	serverIP := net.ParseIP(*server).To4()
	if localIP == nil || serverIP == nil {
		fmt.Fprintln(os.Stderr, "IPv4 required")
		os.Exit(2)
	}
	iface, e := ifaceByIP(localIP)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	group := net.ParseIP(groupFor(*session)).To4()
	tag := sessionTag(*session)
	conn, e := net.ListenMulticastUDP("udp4", iface, &net.UDPAddr{IP: group, Port: *port})
	if e != nil {
		fmt.Fprintln(os.Stderr, "multicast listen:", e)
		os.Exit(3)
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(8 * 1024 * 1024)
	ctrl := &net.UDPAddr{IP: serverIP, Port: *port + 1}
	reply := func(kind byte, w uint32, extra []byte) {
		pl := make([]byte, 6+len(extra))
		copy(pl, client[:])
		copy(pl[6:], extra)
		_, _ = conn.WriteToUDP(pack(tag, kind, w, 0, 0, pl), ctrl)
	}
	cur := uint32(0)
	chunks := map[uint16][]byte{}
	total := uint16(0)
	var recv uint64
	digest := sha256.New()
	lastPacket := time.Now()
	lastHello := time.Time{}
	buf := make([]byte, 65535)
	for {
		now := time.Now()
		if cur == 0 && len(chunks) == 0 && now.Sub(lastHello) >= 500*time.Millisecond {
			reply(kindHello, 0, nil)
			lastHello = now
		}
		if now.Sub(lastPacket) > time.Duration(*timeout)*time.Second {
			fmt.Fprintln(os.Stderr, "multicast receive timeout")
			os.Exit(4)
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, er := conn.ReadFromUDP(buf)
		if ne, ok := er.(net.Error); ok && ne.Timeout() {
			if len(chunks) > 0 && total > 0 {
				miss := make([]int, 0)
				for i := 0; i < int(total); i++ {
					if _, ok := chunks[uint16(i)]; !ok {
						miss = append(miss, i)
					}
				}
				body := make([]byte, len(miss)*2)
				for i, v := range miss {
					binary.BigEndian.PutUint16(body[i*2:], uint16(v))
				}
				reply(kindNack, cur, body)
			}
			continue
		}
		if er != nil {
			fmt.Fprintln(os.Stderr, er)
			os.Exit(4)
		}
		p, ok := unpack(buf[:n], tag)
		if !ok {
			continue
		}
		lastPacket = time.Now()
		switch p.kind {
		case kindBeacon:
			reply(kindHello, cur, nil)
		case kindData:
			if p.window == cur && p.seq < p.total {
				total = p.total
				if _, exists := chunks[p.seq]; !exists {
					chunks[p.seq] = p.payload
				}
			}
		case kindWindowEnd:
			if p.window < cur {
				reply(kindAck, p.window, nil)
				continue
			}
			if p.window != cur {
				continue
			}
			total = p.total
			miss := make([]int, 0)
			for i := 0; i < int(total); i++ {
				if _, ok := chunks[uint16(i)]; !ok {
					miss = append(miss, i)
				}
			}
			if len(miss) > 0 {
				body := make([]byte, len(miss)*2)
				for i, v := range miss {
					binary.BigEndian.PutUint16(body[i*2:], uint16(v))
				}
				reply(kindNack, cur, body)
				continue
			}
			keys := make([]int, 0, len(chunks))
			for k := range chunks {
				keys = append(keys, int(k))
			}
			sort.Ints(keys)
			for _, k := range keys {
				b := chunks[uint16(k)]
				if _, e = os.Stdout.Write(b); e != nil {
					fmt.Fprintln(os.Stderr, "stdout:", e)
					os.Exit(5)
				}
				_, _ = digest.Write(b)
				recv += uint64(len(b))
			}
			reply(kindAck, cur, nil)
			cur++
			chunks = map[uint16][]byte{}
			total = 0
		case kindSessionEnd:
			if len(p.payload) != 40 {
				reply(kindError, cur, []byte("invalid final metadata"))
				fmt.Fprintln(os.Stderr, "invalid final metadata")
				os.Exit(6)
			}
			want := binary.BigEndian.Uint64(p.payload[:8])
			sum := digest.Sum(nil)
			if recv != want || string(sum) != string(p.payload[8:]) {
				msg := fmt.Sprintf("compressed stream verification failed: %d/%d", recv, want)
				reply(kindError, cur, []byte(msg))
				fmt.Fprintln(os.Stderr, msg)
				os.Exit(6)
			}
			for i := 0; i < 3; i++ {
				reply(kindComplete, cur, nil)
			}
			return
		}
	}
}
