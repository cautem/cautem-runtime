//go:build linux

package supervisor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/cautem/cautem-runtime/supervisorcontrol"
)

const processMonitorInterval = 250 * time.Millisecond

type linuxProcessInfo struct {
	PID        int
	ParentPID  int
	GroupID    int
	State      string
	StartTime  string
	Executable string
}

type linuxProcessEventMonitor struct {
	control        *supervisorcontrol.Client
	instance       string
	mainPID        int
	mainExecutable string
	stop           chan struct{}
	done           chan struct{}
	closeOnce      sync.Once
	mu             sync.Mutex
	mainExited     bool
	active         map[int]linuxProcessInfo
}

// startProcessMonitor samples /proc for workload descendants. It never reads
// argv or environment values, which may contain credentials. SIGCHLD-triggered
// scans and wait4 detect adopted-child exits promptly; short-lived descendants
// reaped by their own parent can still escape observation between scans.
func startProcessMonitor(controlClient *supervisorcontrol.Client, instanceID string, mainPID int, executable string) processEventMonitor {
	if controlClient == nil || strings.TrimSpace(instanceID) == "" || mainPID <= 0 {
		return nil
	}
	m := &linuxProcessEventMonitor{
		control: controlClient, instance: instanceID, mainPID: mainPID, mainExecutable: processExecutable(0, executable),
		stop: make(chan struct{}), done: make(chan struct{}), active: make(map[int]linuxProcessInfo),
	}
	m.emit("LAUNCH", mainPID, os.Getpid(), executable)
	go m.run()
	return m
}

func (m *linuxProcessEventMonitor) run() {
	defer close(m.done)
	ticker := time.NewTicker(processMonitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.scan()
		case <-m.stop:
			m.scan()
			m.mu.Lock()
			exits := make([]linuxProcessInfo, 0, len(m.active))
			for pid, process := range m.active {
				exits = append(exits, process)
				delete(m.active, pid)
			}
			m.mu.Unlock()
			for _, process := range exits {
				m.emit("EXIT", process.PID, process.ParentPID, process.Executable)
			}
			return
		}
	}
}

func (m *linuxProcessEventMonitor) MainExit() {
	m.mu.Lock()
	emit := !m.mainExited
	m.mainExited = true
	m.mu.Unlock()
	if emit {
		m.emit("EXIT", m.mainPID, os.Getpid(), m.mainExecutable)
	}
}

// Scan reconciles the workload process tree immediately after SIGCHLD.
func (m *linuxProcessEventMonitor) Scan() {
	if m != nil {
		m.scan()
	}
}

// ChildExit emits an exit as soon as wait4 reaps a tracked adopted child.
func (m *linuxProcessEventMonitor) ChildExit(pid int) {
	if m == nil || pid <= 0 || pid == m.mainPID {
		return
	}
	m.mu.Lock()
	process, ok := m.active[pid]
	if ok {
		delete(m.active, pid)
	}
	m.mu.Unlock()
	if ok {
		m.emit("EXIT", process.PID, process.ParentPID, process.Executable)
	}
}

func (m *linuxProcessEventMonitor) Close() {
	if m == nil {
		return
	}
	m.closeOnce.Do(func() {
		close(m.stop)
		<-m.done
	})
}

func (m *linuxProcessEventMonitor) scan() {
	current, err := readProcessTable()
	if err != nil {
		return
	}
	self := os.Getpid()
	m.mu.Lock()
	events := make([]linuxProcessEvent, 0)
	for pid, previous := range m.active {
		observed, ok := current[pid]
		if !ok || observed.StartTime != previous.StartTime || processHasExited(observed) {
			events = append(events, linuxProcessEvent{activity: "EXIT", pid: pid, parentPID: previous.ParentPID, executable: previous.Executable})
			delete(m.active, pid)
		}
	}

	pids := make([]int, 0, len(current))
	for pid := range current {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	for progress := true; progress; {
		progress = false
		for _, pid := range pids {
			if pid == self || pid == m.mainPID {
				continue
			}
			process := current[pid]
			if active, ok := m.active[pid]; ok && active.StartTime == process.StartTime {
				continue
			}
			if processHasExited(process) {
				continue
			}
			_, parentTracked := m.active[process.ParentPID]
			if !isWorkloadDescendant(process, m.mainPID, self, parentTracked) {
				continue
			}
			process.Executable = processExecutable(pid, "unknown")
			m.active[pid] = process
			events = append(events, linuxProcessEvent{activity: "LAUNCH", pid: pid, parentPID: process.ParentPID, executable: process.Executable})
			progress = true
		}
	}
	m.mu.Unlock()
	for _, event := range events {
		m.emit(event.activity, event.pid, event.parentPID, event.executable)
	}
}

func isWorkloadDescendant(process linuxProcessInfo, mainPID, supervisorPID int, parentTracked bool) bool {
	// A subreaper adopts orphaned workload processes directly. They can have a
	// process group different from the main workload (notably under rootless
	// Podman), so parentage to the supervisor is sufficient to keep tracking.
	return process.ParentPID == mainPID || parentTracked || process.ParentPID == supervisorPID || process.GroupID == mainPID
}

type linuxProcessEvent struct {
	activity   string
	pid        int
	parentPID  int
	executable string
}

func (m *linuxProcessEventMonitor) emit(activity string, pid, parentPID int, executable string) {
	if pid <= 0 || parentPID < 0 {
		return
	}
	event := supervisorcontrol.ProcessEvent{
		InstanceID: m.instance, Activity: activity, PID: pid, ParentPID: parentPID,
		Executable: processExecutable(0, executable), Timestamp: time.Now().UTC().UnixMilli(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := m.control.Call(ctx, supervisorcontrol.Request{
		Operation: supervisorcontrol.OperationProcess, InstanceID: m.instance, Process: &event,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cautem-supervisor: process event delivery failed: %v\n", err)
	}
}

func readProcessTable() (map[int]linuxProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	processes := make(map[int]linuxProcessInfo, len(entries))
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		process, ok := readProcessInfo(pid)
		if ok {
			processes[pid] = process
		}
	}
	return processes, nil
}

func readProcessInfo(pid int) (linuxProcessInfo, bool) {
	stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return linuxProcessInfo{}, false
	}
	closeParen := strings.LastIndexByte(string(stat), ')')
	if closeParen < 0 {
		return linuxProcessInfo{}, false
	}
	fields := strings.Fields(string(stat[closeParen+1:]))
	// Fields begin with state (field 3), followed by ppid, pgrp and starttime
	// at offset 19 (kernel stat field 22).
	if len(fields) < 20 {
		return linuxProcessInfo{}, false
	}
	parentPID, err := strconv.Atoi(fields[1])
	if err != nil || parentPID < 0 {
		return linuxProcessInfo{}, false
	}
	groupID, err := strconv.Atoi(fields[2])
	if err != nil || groupID < 0 {
		return linuxProcessInfo{}, false
	}
	return linuxProcessInfo{PID: pid, ParentPID: parentPID, GroupID: groupID, State: fields[0], StartTime: fields[19]}, true
}

func processHasExited(process linuxProcessInfo) bool {
	return process.State == "Z" || process.State == "X" || process.State == "x"
}

func processExecutable(pid int, fallback string) string {
	name := fallback
	if pid > 0 {
		if path, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe")); err == nil {
			name = path
		}
	}
	name = strings.TrimSuffix(name, " (deleted)")
	name = filepath.Base(name)
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return '_'
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if len(name) > 255 {
		name = name[:255]
		for !utf8.ValidString(name) {
			name = name[:len(name)-1]
		}
	}
	if name == "" || name == "." || name == string(filepath.Separator) {
		return "unknown"
	}
	return name
}
