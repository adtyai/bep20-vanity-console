package job

import (
	"os"
	"strings"
	"testing"
)

func TestLogicalCPUsIncludeBothSockets(t *testing.T) {
	online := "0-23,48-71\n"
	stat := "cpu  1 0 0 0 0 0 0 0 0 0\n" +
		statCPUs(0, 24) +
		statCPUs(48, 72)
	ids := chooseLogicalCPUs(online, stat, 8)
	if len(ids) != 48 {
		t.Fatalf("got %d cpus, want 48 from both sockets", len(ids))
	}
	if ids[0] != 0 || ids[23] != 23 || ids[24] != 48 || ids[47] != 71 {
		t.Fatalf("ids = %v", ids)
	}
}

func TestLogicalCPUsIgnoreAggregateStatLine(t *testing.T) {
	ids := chooseLogicalCPUs("0-1", "cpu  9 0 0 0\ncpu0 1 0 0 0\ncpu1 1 0 0 0\n", 1)
	if len(ids) != 2 || ids[0] != 0 || ids[1] != 1 {
		t.Fatalf("ids = %v", ids)
	}
}

func TestCgroupLimitParsesQuotaAndUnlimited(t *testing.T) {
	cpus, cap, limited := cgroupLimitCPUs("2400000 100000", "", "")
	if !limited || cpus != 24 || cap != 0 {
		t.Fatalf("quota = %d cap %d limited %v, want 24", cpus, cap, limited)
	}
	cpus, cap, limited = cgroupLimitCPUs("max 100000", "50000", "100000")
	if limited || cpus != 0 || cap != 0 {
		t.Fatalf("v2 max must ignore stale v1 quota, got %d %d %v", cpus, cap, limited)
	}
	cpus, cap, limited = cgroupLimitCPUs("110000 100000", "", "")
	if !limited || cpus != 1 || cap != 0 {
		t.Fatalf("fractional quota = %d cap %d, want 1 core not 2", cpus, cap)
	}
	cpus, cap, limited = cgroupLimitCPUs("", "40000", "100000")
	if !limited || cpus != 0 || cap != 40 {
		t.Fatalf("sub-one quota = %d cap %d limited %v, want cap 40", cpus, cap, limited)
	}
}

func TestUsableCapacityUsesTheTightestPositiveLimit(t *testing.T) {
	if n := usableCapacity(40, 24, 0, 8, true); n != 24 {
		t.Fatalf("affinity = %d, want 24", n)
	}
	if n := usableCapacity(40, 40, 24, 8, true); n != 24 {
		t.Fatalf("quota = %d, want 24", n)
	}
	if n := usableCapacity(0, 0, 0, 0, true); n != 1 {
		t.Fatalf("empty = %d, want 1", n)
	}
}

func TestUsableCapacityDoesNotUseDetectedWhenAffinityFails(t *testing.T) {
	if n := usableCapacity(40, 0, 0, 8, false); n != 8 {
		t.Fatalf("failed affinity used detected count %d, want visible 8", n)
	}
	if n := usableCapacity(40, 0, 24, 40, false); n != 24 {
		t.Fatalf("failed affinity ignored quota %d, want 24", n)
	}
}

func TestUsableCapacityDoesNotShrinkALargerAffinity(t *testing.T) {
	if n := usableCapacity(24, 40, 0, 8, true); n != 40 {
		t.Fatalf("under-reported detection capped affinity %d, want 40", n)
	}
}

func TestZeroQuotaIsNotUnlimited(t *testing.T) {
	cpus, cap, limited := cgroupLimitCPUs("0 100000", "", "")
	if !limited || cpus != 0 || cap != 0 {
		t.Fatalf("v2 zero quota = %d cap %d limited %v", cpus, cap, limited)
	}
	cpus, cap, limited = cgroupLimitCPUs("", "-1", "100000")
	if limited || cpus != 0 || cap != 0 {
		t.Fatalf("v1 -1 = %d cap %d limited %v", cpus, cap, limited)
	}
	cpus, cap, limited = cgroupLimitCPUs("", "0", "100000")
	if limited || cpus != 0 || cap != 0 {
		t.Fatalf("v1 zero = %d cap %d limited %v", cpus, cap, limited)
	}
	_, _, _, ok := parseCgroupFile("0 0", "", "", 2)
	if ok {
		t.Fatal("v2 zero period parsed as a quota")
	}
}

func TestZeroQuotaSleepsTheWindow(t *testing.T) {
	force, duty := dutyFromQuota(0, 0, true)
	if !force || duty != -1 {
		t.Fatalf("zero quota = force %v duty %d", force, duty)
	}
}

func TestUnreadCgroupLeavesRuntimeProcs(t *testing.T) {
	if overrideRuntimeProcs(false) {
		t.Fatal("unread cgroup overrode runtime processor count")
	}
	if !overrideRuntimeProcs(true) {
		t.Fatal("measured limit was not applied")
	}
}

func TestAffinityProbeOnlyReads(t *testing.T) {
	b, err := os.ReadFile("hostcpu_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "SchedSetaffinity") {
		t.Fatal("affinity probe writes the process mask")
	}
}

func TestCPUCgroupPathUsesTheProcessCgroup(t *testing.T) {
	cgroupText := "2:cpuacct:/wrong\n2:cpu,cpuacct:/docker/abc\n0::/system.slice/docker-abc.scope\n"
	mountinfo := "" +
		"20 11 0:20 / /sys/fs/cgroup/cpu\040acct rw - cgroup cgroup rw,cpuacct\n" +
		"21 11 0:21 / /sys/fs/cgroup/cpu,cpuacct rw - cgroup cgroup rw,cpu,cpuacct\n" +
		"22 11 0:22 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n"
	dir, mount, version := cpuCgroupMount(cgroupText, mountinfo)
	if version != 1 || dir != "/sys/fs/cgroup/cpu,cpuacct/docker/abc" || mount != "/sys/fs/cgroup/cpu,cpuacct" {
		t.Fatalf("v1 path = %q mount %q version %d", dir, mount, version)
	}

	cgroupText = "0::/system.slice/docker-abc.scope\n"
	dir, mount, version = cpuCgroupMount(cgroupText, mountinfo)
	if version != 2 || dir != "/sys/fs/cgroup/system.slice/docker-abc.scope" || mount != "/sys/fs/cgroup" {
		t.Fatalf("v2 path = %q mount %q version %d", dir, mount, version)
	}

	cgroupText = "2:cpu:/docker/abc\n"
	mountinfo = "21 11 0:21 / /sys/fs/cgroup/cpu\\040set rw - cgroup cgroup rw,cpu\n"
	dir, mount, version = cpuCgroupMount(cgroupText, mountinfo)
	if version != 1 || dir != "/sys/fs/cgroup/cpu set/docker/abc" || mount != "/sys/fs/cgroup/cpu set" {
		t.Fatalf("escaped mount = %q %q version %d", dir, mount, version)
	}

	cgroupText = "0::/sandbox/container\n"
	mountinfo = "22 11 0:22 /sandbox /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n"
	dir, mount, version = cpuCgroupMount(cgroupText, mountinfo)
	if version != 2 || dir != "/sys/fs/cgroup/container" || mount != "/sys/fs/cgroup" {
		t.Fatalf("mount root prefix = %q %q version %d", dir, mount, version)
	}
}

func TestTightestQuotaUsesParentInsideTheMount(t *testing.T) {
	dirs := ancestorDirs("/sys/fs/cgroup/system.slice/docker.scope", "/sys/fs/cgroup")
	if len(dirs) != 3 || dirs[2] != "/sys/fs/cgroup" {
		t.Fatalf("dirs = %v", dirs)
	}
	files := map[string]string{
		"/sys/fs/cgroup/system.slice/docker.scope/cpu.max": "max 100000",
		"/sys/fs/cgroup/system.slice/cpu.max":              "2400000 100000",
		"/sys/fs/cgroup/cpu.max":                           "max 100000",
	}
	cpus, cap, limited, ok := tightestQuota(dirs, 2, func(dir string, version int) (int, int, bool, bool) {
		if version != 2 {
			t.Fatalf("version %d", version)
		}
		text, found := files[dir+"/cpu.max"]
		if !found {
			return 0, 0, false, false
		}
		return parseCgroupFile(text, "", "", 2)
	})
	if !ok || !limited || cpus != 24 || cap != 0 {
		t.Fatalf("parent quota = %d cap %d limited %v ok %v", cpus, cap, limited, ok)
	}
}

func TestStartupLimitReasonNamesTheTighterConstraint(t *testing.T) {
	if got := startupLimitReason(40, 24, 40, 24, true, true, true); got != "cpu_cgroup" {
		t.Fatalf("cgroup reason = %q", got)
	}
	if got := startupLimitReason(40, 20, 20, 24, true, true, true); got != "cpu_affinity" {
		t.Fatalf("affinity reason = %q", got)
	}
	if got := startupLimitReason(40, 8, 0, 0, false, false, true); got != "cpu_affinity" {
		t.Fatalf("failed affinity reason = %q", got)
	}
	if got := startupLimitReason(40, 40, 40, 0, true, false, false); got != "cpu_cgroup" {
		t.Fatalf("unread cgroup reason = %q", got)
	}
}

func TestClampDutyDoesNotExceedSubOneQuota(t *testing.T) {
	if n := clampDuty(90, 40); n != 40 {
		t.Fatalf("capped = %d, want 40", n)
	}
	if n := clampDuty(30, 40); n != 30 {
		t.Fatalf("under cap = %d, want 30", n)
	}
	if n := clampDuty(90, 0); n != 90 {
		t.Fatalf("no cap = %d, want 90", n)
	}
	if n := clampDuty(200, 0); n != 200 {
		t.Fatalf("full duty = %d, want 200", n)
	}
	if n := clampDuty(90, -1); n != 0 {
		t.Fatalf("empty quota = %d, want 0", n)
	}
}

func TestLiveCgroupPathIfPresent(t *testing.T) {
	cg, err1 := os.ReadFile("/proc/self/cgroup")
	mi, err2 := os.ReadFile("/proc/self/mountinfo")
	if err1 != nil || err2 != nil {
		t.Skip("no cgroup files")
	}
	dir, mount, version := cpuCgroupMount(string(cg), string(mi))
	if version == 0 {
		t.Skip("no cpu cgroup")
	}
	if dir == "" {
		t.Fatalf("cgroup version %d has no mount path", version)
	}
	if mount != "/" && dir != mount && !strings.HasPrefix(dir, mount+"/") {
		t.Fatalf("dir %q outside mount %q", dir, mount)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("cgroup dir %q: %v", dir, err)
	}
	t.Logf("cgroup v%d dir %s", version, dir)
}

func TestLogicalCPUsFallbackWhenListsEmpty(t *testing.T) {
	ids := chooseLogicalCPUs("", "cpu  1 0 0 0\n", 4)
	if len(ids) != 4 {
		t.Fatalf("ids = %v", ids)
	}
}

func statCPUs(from, to int) string {
	var b []byte
	for i := from; i < to; i++ {
		b = append(b, []byte("cpu"+itoa(i)+" 1 0 0 0\n")...)
	}
	return string(b)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d [8]byte
	i := len(d)
	for n > 0 {
		i--
		d[i] = byte('0' + n%10)
		n /= 10
	}
	return string(d[i:])
}
