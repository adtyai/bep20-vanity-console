//go:build linux

package job

import (
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/unix"
)

func startHostWorkers(logf Logger) (workers, host, usable, dutyCap int, quotaUnknown bool) {
	online, _ := os.ReadFile("/sys/devices/system/cpu/online")
	stat, _ := os.ReadFile("/proc/stat")
	visible := runtime.NumCPU()
	ids := chooseLogicalCPUs(string(online), string(stat), visible)
	detected := len(ids)
	affinity, affinityOK := readAffinity()
	cpus, cap, limited, readOK := readProcessCgroup()
	cgroupLimit := 0
	if limited && cpus >= 1 {
		cgroupLimit = cpus
	}
	usable = usableCapacity(detected, affinity, cgroupLimit, visible, affinityOK)
	if force, duty := dutyFromQuota(cpus, cap, limited); force {
		usable = 1
		dutyCap = duty
	}
	host = detected
	if host < usable {
		host = usable
	}
	if usable > 1024 {
		usable = 1024
	}
	if overrideRuntimeProcs(readOK) {
		runtime.GOMAXPROCS(usable)
	}
	if reason := startupLimitReason(host, usable, affinity, cpus, affinityOK, limited, readOK); reason != "" && logf != nil {
		logf("error", "", int64(host), uint64(usable), reason)
	}
	return usable, host, usable, dutyCap, !readOK
}

func readProcessCgroup() (cpus, dutyCap int, limited, readOK bool) {
	cg, err1 := os.ReadFile("/proc/self/cgroup")
	mi, err2 := os.ReadFile("/proc/self/mountinfo")
	if err1 != nil || err2 != nil {
		return 0, 0, false, false
	}
	dir, mount, version := cpuCgroupMount(string(cg), string(mi))
	if version == 0 {
		return 0, 0, false, true
	}
	if dir == "" {
		return 0, 0, false, false
	}
	return tightestQuota(ancestorDirs(dir, mount), version, readQuotaDir)
}

func readQuotaDir(dir string, version int) (int, int, bool, bool) {
	if version == 2 {
		b, err := os.ReadFile(filepath.Join(dir, "cpu.max"))
		if err != nil {
			return 0, 0, false, false
		}
		return parseCgroupFile(string(b), "", "", 2)
	}
	q, err1 := os.ReadFile(filepath.Join(dir, "cpu.cfs_quota_us"))
	p, err2 := os.ReadFile(filepath.Join(dir, "cpu.cfs_period_us"))
	if err1 != nil || err2 != nil {
		return 0, 0, false, false
	}
	return parseCgroupFile("", string(q), string(p), 1)
}

func readAffinity() (int, bool) {
	var got unix.CPUSet
	if err := unix.SchedGetaffinity(0, &got); err != nil {
		return 0, false
	}
	n := 0
	for id := 0; id < 1024; id++ {
		if got.IsSet(id) {
			n++
		}
	}
	if n < 1 {
		return 0, false
	}
	return n, true
}
