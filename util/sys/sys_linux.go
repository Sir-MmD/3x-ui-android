//go:build linux
// +build linux

package sys

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"
	"strings"
	"sync"
	"syscall"
)

var SIGUSR1 = syscall.SIGUSR1

func getLinesNum(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	sum := 0
	buf := make([]byte, 8192)
	for {
		n, err := file.Read(buf)

		var buffPosition int
		for {
			i := bytes.IndexByte(buf[buffPosition:n], '\n')
			if i < 0 {
				break
			}
			buffPosition += i + 1
			sum++
		}

		if err == io.EOF {
			break
		} else if err != nil {
			return 0, err
		}
	}
	return sum, nil
}

// getConnectionCount tries to count lines from /proc/net/<proto> first,
// falling back to /proc/self/net/<proto> for restricted environments (Android).
func getConnectionCount(proto string) (int, error) {
	root := HostProc()

	v4, err := safeGetLinesNum(fmt.Sprintf("%v/net/%s", root, proto))
	if err != nil {
		// Fallback to /proc/self/net/ (accessible on Android)
		v4, err = safeGetLinesNum(fmt.Sprintf("/proc/self/net/%s", proto))
		if err != nil {
			return 0, err
		}
		v6, err := safeGetLinesNum(fmt.Sprintf("/proc/self/net/%s6", proto))
		if err != nil {
			return 0, err
		}
		return v4 + v6, nil
	}
	v6, err := safeGetLinesNum(fmt.Sprintf("%v/net/%s6", root, proto))
	if err != nil {
		return v4, nil
	}
	return v4 + v6, nil
}

// GetTCPCount returns the number of active TCP connections.
func GetTCPCount() (int, error) {
	n, err := getConnectionCount("tcp")
	if err != nil {
		// Fallback: netlink SOCK_DIAG
		return GetConnectionCountNetlink(syscall.IPPROTO_TCP)
	}
	return n, nil
}

// GetUDPCount returns the number of active UDP connections.
func GetUDPCount() (int, error) {
	n, err := getConnectionCount("udp")
	if err != nil {
		// Fallback: netlink SOCK_DIAG
		return GetConnectionCountNetlink(syscall.IPPROTO_UDP)
	}
	return n, nil
}

// safeGetLinesNum returns 0 if the file does not exist, otherwise forwards
// to getLinesNum to count the number of lines.
func safeGetLinesNum(path string) (int, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	return getLinesNum(path)
}

// --- CPU Utilization (Linux native) ---

var (
	cpuMu       sync.Mutex
	lastTotal   uint64
	lastIdleAll uint64
	hasLast     bool
)

// openProcFile opens a /proc file using raw syscalls to avoid faccessat2
// which is blocked by Android's seccomp filter.
func openProcFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// CPUPercentRaw returns instantaneous total CPU utilization by reading /proc/stat.
// First call initializes and returns 0; subsequent calls return busy/total * 100.
func CPUPercentRaw() (float64, error) {
	f, err := openProcFile("/proc/stat")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	rd := bufio.NewReader(f)
	line, err := rd.ReadString('\n')
	if err != nil && err != io.EOF {
		return 0, err
	}
	// Expect line like: cpu  user nice system idle iowait irq softirq steal guest guest_nice
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, fmt.Errorf("unexpected /proc/stat format")
	}

	var nums []uint64
	for i := 1; i < len(fields); i++ {
		v, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			break
		}
		nums = append(nums, v)
	}
	if len(nums) < 4 { // need at least user,nice,system,idle
		return 0, fmt.Errorf("insufficient cpu fields")
	}

	// Conform with standard Linux CPU accounting
	var user, nice, system, idle, iowait, irq, softirq, steal uint64
	user = nums[0]
	if len(nums) > 1 {
		nice = nums[1]
	}
	if len(nums) > 2 {
		system = nums[2]
	}
	if len(nums) > 3 {
		idle = nums[3]
	}
	if len(nums) > 4 {
		iowait = nums[4]
	}
	if len(nums) > 5 {
		irq = nums[5]
	}
	if len(nums) > 6 {
		softirq = nums[6]
	}
	if len(nums) > 7 {
		steal = nums[7]
	}

	idleAll := idle + iowait
	nonIdle := user + nice + system + irq + softirq + steal
	total := idleAll + nonIdle

	cpuMu.Lock()
	defer cpuMu.Unlock()

	if !hasLast {
		lastTotal = total
		lastIdleAll = idleAll
		hasLast = true
		return 0, nil
	}

	totald := total - lastTotal
	idled := idleAll - lastIdleAll
	lastTotal = total
	lastIdleAll = idleAll

	if totald == 0 {
		return 0, nil
	}
	busy := totald - idled
	pct := float64(busy) / float64(totald) * 100.0
	if pct > 100 {
		pct = 100
	}
	return pct, nil
}

// CPUPercentFromCpuidle computes CPU utilization from /sys/devices/system/cpu/cpu*/cpuidle/state*/time.
// This works on Android where /proc/stat is not readable by untrusted apps.
// Returns busy percentage (0-100). First call initializes; second call returns real value.
var (
	cpuidleMu       sync.Mutex
	lastIdleTotal   uint64
	lastIdleTimeNs  int64
	hasLastIdle     bool
	cpuidleNumCPUs  int
	cpuidlePaths    []string
	cpuidleScanned  bool
)

func scanCpuidlePaths() {
	if cpuidleScanned {
		return
	}
	cpuidleScanned = true
	cpuDirs, err := os.ReadDir("/sys/devices/system/cpu")
	if err != nil {
		return
	}
	for _, d := range cpuDirs {
		name := d.Name()
		if len(name) < 4 || name[:3] != "cpu" || name[3] < '0' || name[3] > '9' {
			continue
		}
		cpuidleNumCPUs++
		cpuPath := "/sys/devices/system/cpu/" + name + "/cpuidle"
		states, err := os.ReadDir(cpuPath)
		if err != nil {
			continue
		}
		for _, s := range states {
			if strings.HasPrefix(s.Name(), "state") {
				cpuidlePaths = append(cpuidlePaths, cpuPath+"/"+s.Name()+"/time")
			}
		}
	}
}

func readCpuidleTotal() (uint64, error) {
	scanCpuidlePaths()
	if len(cpuidlePaths) == 0 {
		return 0, fmt.Errorf("no cpuidle paths found")
	}
	var total uint64
	buf := make([]byte, 32)
	for _, path := range cpuidlePaths {
		fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
		if err != nil {
			continue
		}
		n, _ := syscall.Read(fd, buf)
		syscall.Close(fd)
		if n > 0 {
			s := strings.TrimSpace(string(buf[:n]))
			v, _ := strconv.ParseUint(s, 10, 64)
			total += v
		}
	}
	return total, nil
}

// CPUPercentFromCpuidle returns CPU busy percentage using cpuidle sysfs counters.
func CPUPercentFromCpuidle() (float64, error) {
	idleTotal, err := readCpuidleTotal()
	if err != nil {
		return 0, err
	}
	nowNs := time.Now().UnixNano()

	cpuidleMu.Lock()
	defer cpuidleMu.Unlock()

	if !hasLastIdle {
		lastIdleTotal = idleTotal
		lastIdleTimeNs = nowNs
		hasLastIdle = true
		return 0, nil
	}

	dtUs := float64(nowNs-lastIdleTimeNs) / 1000.0 // wall time in microseconds
	diUs := float64(idleTotal - lastIdleTotal)       // idle delta in microseconds (cpuidle reports µs)

	lastIdleTotal = idleTotal
	lastIdleTimeNs = nowNs

	if dtUs <= 0 || cpuidleNumCPUs <= 0 {
		return 0, nil
	}

	busyPct := 100.0 - (diUs*100.0)/(dtUs*float64(cpuidleNumCPUs))
	if busyPct < 0 {
		busyPct = 0
	}
	if busyPct > 100 {
		busyPct = 100
	}
	return busyPct, nil
}

// SwapMemoryFromMeminfo reads swap info from /proc/meminfo as a fallback
// when /proc/vmstat is not accessible (e.g., Android).
func SwapMemoryFromMeminfo() (used, total uint64, err error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	var swapTotal, swapFree uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "SwapTotal:") {
			swapTotal = parseMemInfoKB(line)
		} else if strings.HasPrefix(line, "SwapFree:") {
			swapFree = parseMemInfoKB(line)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	return swapTotal - swapFree, swapTotal, nil
}

func parseMemInfoKB(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, _ := strconv.ParseUint(fields[1], 10, 64)
	return v * 1024 // /proc/meminfo values are in kB
}

// NetIOCountersFallback reads network IO from /proc/self/net/dev as a fallback,
// then tries netlink RTM_GETLINK if /proc is not accessible (e.g., Android).
func NetIOCountersFallback() (bytesSent, bytesRecv uint64, err error) {
	// Try /proc/self/net/dev first
	if f, ferr := os.Open("/proc/self/net/dev"); ferr == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			if lineNum <= 2 {
				continue
			}
			line := scanner.Text()
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			fields := strings.Fields(parts[1])
			if len(fields) < 10 {
				continue
			}
			rx, _ := strconv.ParseUint(fields[0], 10, 64)
			tx, _ := strconv.ParseUint(fields[8], 10, 64)
			bytesRecv += rx
			bytesSent += tx
		}
		if scanner.Err() == nil && (bytesSent > 0 || bytesRecv > 0) {
			return bytesSent, bytesRecv, nil
		}
	}

	// Fallback: netlink RTM_GETLINK
	return netlinkNetIO()
}

// netlinkNetIO gets network IO counters via netlink RTM_GETLINK messages.
func netlinkNetIO() (bytesSent, bytesRecv uint64, err error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return 0, 0, err
	}
	defer syscall.Close(fd)

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, sa); err != nil {
		return 0, 0, err
	}

	// Build RTM_GETLINK request
	req := make([]byte, 40) // nlmsghdr(16) + ifinfomsg(16) + padding
	// nlmsghdr
	nlPut32(req, 0, 40)                    // Length
	nlPut16(req, 4, 18)                    // Type: RTM_GETLINK
	nlPut16(req, 6, syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP) // Flags
	nlPut32(req, 8, 1)                     // Seq
	// ifinfomsg
	req[16] = syscall.AF_UNSPEC

	if err := syscall.Sendto(fd, req, 0, sa); err != nil {
		return 0, 0, err
	}

	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return 0, 0, err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return 0, 0, err
		}
		done := false
		for _, msg := range msgs {
			if msg.Header.Type == syscall.NLMSG_DONE {
				done = true
				break
			}
			if msg.Header.Type == syscall.NLMSG_ERROR {
				done = true
				break
			}
			if msg.Header.Type != 16 { // RTM_NEWLINK
				continue
			}
			// Parse attributes from ifinfomsg (16 bytes) onwards
			if len(msg.Data) < 16 {
				continue
			}
			attrs, err := syscall.ParseNetlinkRouteAttr(&msg)
			if err != nil {
				continue
			}
			for _, attr := range attrs {
				// IFLA_STATS64 = 23, contains rtnl_link_stats64
				if attr.Attr.Type == 23 && len(attr.Value) >= 48 {
					bytesRecv += nlGet64(attr.Value, 0)  // rx_bytes
					bytesSent += nlGet64(attr.Value, 40) // tx_bytes (offset 40 in rtnl_link_stats64)
				}
				// IFLA_STATS = 7, contains rtnl_link_stats (32-bit)
				if attr.Attr.Type == 7 && len(attr.Value) >= 24 && bytesSent == 0 && bytesRecv == 0 {
					bytesRecv += uint64(nlGet32(attr.Value, 0))  // rx_bytes
					bytesSent += uint64(nlGet32(attr.Value, 20)) // tx_bytes
				}
			}
		}
		if done {
			break
		}
	}
	return bytesSent, bytesRecv, nil
}

// GetConnectionCountNetlink gets TCP/UDP connection count via netlink SOCK_DIAG.
func GetConnectionCountNetlink(proto uint8) (int, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, 4) // NETLINK_SOCK_DIAG
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, sa); err != nil {
		return 0, err
	}

	// Send for both IPv4 and IPv6
	count := 0
	for _, family := range []uint8{syscall.AF_INET, syscall.AF_INET6} {
		c, err := diagCount(fd, sa, family, proto)
		if err != nil {
			continue
		}
		count += c
	}
	return count, nil
}

func diagCount(fd int, sa *syscall.SockaddrNetlink, family, proto uint8) (int, error) {
	// inet_diag_req_v2 structure
	req := make([]byte, 72)
	// nlmsghdr
	nlPut32(req, 0, 72)                    // Length
	nlPut16(req, 4, 20)                    // Type: SOCK_DIAG_BY_FAMILY
	nlPut16(req, 6, syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
	nlPut32(req, 8, 1)                     // Seq
	// inet_diag_req_v2 at offset 16
	req[16] = family                       // sdiag_family
	req[17] = proto                        // sdiag_protocol
	// idiag_states: all established-like states (bitmask)
	nlPut32(req, 20, 0xFFF) // all states

	if err := syscall.Sendto(fd, req, 0, sa); err != nil {
		return 0, err
	}

	count := 0
	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return count, err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return count, err
		}
		done := false
		for _, msg := range msgs {
			if msg.Header.Type == syscall.NLMSG_DONE {
				done = true
				break
			}
			if msg.Header.Type == syscall.NLMSG_ERROR {
				done = true
				break
			}
			if msg.Header.Type == 20 { // SOCK_DIAG_BY_FAMILY
				count++
			}
		}
		if done {
			break
		}
	}
	return count, nil
}

// Helper functions for netlink message encoding/decoding
func nlPut16(b []byte, off int, v uint16) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
}

func nlPut32(b []byte, off int, v uint32) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
	b[off+2] = byte(v >> 16)
	b[off+3] = byte(v >> 24)
}

func nlGet32(b []byte, off int) uint32 {
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}

func nlGet64(b []byte, off int) uint64 {
	return uint64(nlGet32(b, off)) | uint64(nlGet32(b, off+4))<<32
}
