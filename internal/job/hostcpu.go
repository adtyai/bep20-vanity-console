package job

import (
	"path"
	"sort"
	"strconv"
	"strings"
)

func usableCapacity(detected, affinity, cgroupLimit, visible int, affinityOK bool) int {
	n := 0
	consider := func(v int) {
		if v < 1 {
			return
		}
		if n == 0 || v < n {
			n = v
		}
	}
	if affinityOK && affinity >= 1 {
		consider(affinity)
	} else {
		consider(visible)
	}
	consider(cgroupLimit)
	if n < 1 {
		return 1
	}
	if n > 1024 {
		return 1024
	}
	return n
}

func chooseLogicalCPUs(online, stat string, fallback int) []int {
	seen := map[int]struct{}{}
	add := func(id int) {
		if id < 0 || id >= 1024 {
			return
		}
		seen[id] = struct{}{}
	}
	for _, id := range parseOnlineList(online) {
		add(id)
	}
	for _, id := range parseStatCPUs(stat) {
		add(id)
	}
	if len(seen) == 0 {
		if fallback < 1 {
			return nil
		}
		if fallback > 1024 {
			fallback = 1024
		}
		ids := make([]int, fallback)
		for i := range ids {
			ids[i] = i
		}
		return ids
	}
	ids := make([]int, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

func parseOnlineList(s string) []int {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var ids []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if dash := strings.IndexByte(part, '-'); dash >= 0 {
			lo, err1 := strconv.Atoi(part[:dash])
			hi, err2 := strconv.Atoi(part[dash+1:])
			if err1 != nil || err2 != nil || hi < lo || hi-lo > 1024 {
				continue
			}
			for id := lo; id <= hi; id++ {
				ids = append(ids, id)
			}
			continue
		}
		id, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	return ids
}

func cgroupLimitCPUs(cpuMax, quotaFile, periodFile string) (cpus, dutyCap int, limited bool) {
	if strings.TrimSpace(cpuMax) != "" {
		cpus, dutyCap, limited, _ = parseCgroupFile(cpuMax, "", "", 2)
		return
	}
	cpus, dutyCap, limited, _ = parseCgroupFile("", quotaFile, periodFile, 1)
	return
}

func parseCgroupFile(cpuMax, quotaFile, periodFile string, version int) (cpus, dutyCap int, limited, ok bool) {
	if version == 2 {
		fields := strings.Fields(cpuMax)
		if len(fields) == 0 {
			return 0, 0, false, false
		}
		if fields[0] == "max" {
			return 0, 0, false, true
		}
		if len(fields) < 2 {
			return 0, 0, false, false
		}
		quota, err1 := strconv.ParseInt(fields[0], 10, 64)
		period, err2 := strconv.ParseInt(fields[1], 10, 64)
		if err1 != nil || err2 != nil || period <= 0 {
			return 0, 0, false, false
		}
		cpus, dutyCap, limited = quotaPair(quota, period)
		return cpus, dutyCap, limited, true
	}
	quota, err1 := strconv.ParseInt(strings.TrimSpace(quotaFile), 10, 64)
	period, err2 := strconv.ParseInt(strings.TrimSpace(periodFile), 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false, false
	}
	if quota <= 0 || period <= 0 {
		return 0, 0, false, true
	}
	cpus, dutyCap, limited = quotaPair(quota, period)
	return cpus, dutyCap, limited, true
}

func quotaPair(quota, period int64) (cpus, dutyCap int, limited bool) {
	if quota < 0 || period <= 0 {
		return 0, 0, false
	}
	if quota == 0 {
		return 0, 0, true
	}
	cpus64 := quota / period
	if cpus64 >= 1 {
		if cpus64 > 1024 {
			cpus64 = 1024
		}
		return int(cpus64), 0, true
	}
	cap := quota * 100 / period
	if cap > 99 {
		cap = 99
	}
	return 0, int(cap), true
}

func dutyFromQuota(cpus, cap int, limited bool) (forceOne bool, dutyCap int) {
	if !limited || cpus >= 1 {
		return false, 0
	}
	if cap < 1 {
		return true, -1
	}
	return true, cap
}

func overrideRuntimeProcs(readOK bool) bool {
	return readOK
}

func clampDuty(percent, dutyCap int) int {
	if percent < 5 {
		percent = 5
	}
	if percent > 500 {
		percent = 500
	}
	if dutyCap < 0 {
		return 0
	}
	if dutyCap > 0 && percent > dutyCap {
		return dutyCap
	}
	return percent
}

func startupLimitReason(host, usable, affinity, cgroupCPUs int, affinityOK, cgroupLimited, cgroupReadOK bool) string {
	if !cgroupReadOK {
		return "cpu_cgroup"
	}
	cgroupWins := cgroupLimited && cgroupCPUs >= 1 && cgroupCPUs == usable && usable < host && (!affinityOK || affinity < 1 || cgroupCPUs <= affinity)
	cgroupWins = cgroupWins || (cgroupLimited && cgroupCPUs < 1 && usable < host)
	if cgroupWins {
		return "cpu_cgroup"
	}
	if !affinityOK {
		return "cpu_affinity"
	}
	if affinity >= 1 && affinity < host && usable < host {
		return "cpu_affinity"
	}
	return ""
}

func cpuCgroupMount(cgroupText, mountinfo string) (dir, mount string, version int) {
	path, version := parseSelfCgroup(cgroupText)
	if version == 0 {
		return "", "", 0
	}
	dir, mount = mountForCgroup(mountinfo, path, version)
	return dir, mount, version
}

func parseSelfCgroup(text string) (path string, version int) {
	var v2 string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || !strings.HasPrefix(parts[2], "/") {
			continue
		}
		if parts[0] != "0" && hasController(parts[1], "cpu") {
			return parts[2], 1
		}
		if parts[0] == "0" {
			v2 = parts[2]
		}
	}
	if v2 != "" {
		return v2, 2
	}
	return "", 0
}

func hasController(list, name string) bool {
	for _, c := range strings.Split(list, ",") {
		if c == name {
			return true
		}
	}
	return false
}

func mountForCgroup(mountinfo, cgroupPath string, version int) (dir, mount string) {
	for _, line := range strings.Split(mountinfo, "\n") {
		root, mnt, fstype, super, ok := mountFields(line)
		if !ok {
			continue
		}
		if version == 2 && fstype != "cgroup2" {
			continue
		}
		if version == 1 && (fstype != "cgroup" || !hasController(super, "cpu")) {
			continue
		}
		root, ok1 := unescapeMountPath(root)
		mnt, ok2 := unescapeMountPath(mnt)
		if !ok1 || !ok2 || !strings.HasPrefix(root, "/") || !strings.HasPrefix(mnt, "/") {
			continue
		}
		joined, ok := joinCgroupDir(mnt, root, cgroupPath)
		if !ok {
			continue
		}
		return joined, path.Clean(mnt)
	}
	return "", ""
}

func mountFields(line string) (root, mnt, fstype, super string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	sep := strings.Index(line, " - ")
	if sep < 0 {
		return
	}
	head := strings.Fields(line[:sep])
	tail := strings.Fields(line[sep+3:])
	if len(head) < 5 || len(tail) < 1 {
		return
	}
	root = head[3]
	mnt = head[4]
	fstype = tail[0]
	if len(tail) >= 3 {
		super = tail[2]
	}
	return root, mnt, fstype, super, true
}

func unescapeMountPath(s string) (string, bool) {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+3 >= len(s) {
			return "", false
		}
		o1, o2, o3 := s[i+1], s[i+2], s[i+3]
		if o1 < '0' || o1 > '7' || o2 < '0' || o2 > '7' || o3 < '0' || o3 > '7' {
			return "", false
		}
		b.WriteByte((o1-'0')*64 + (o2-'0')*8 + (o3 - '0'))
		i += 3
	}
	return b.String(), true
}

func joinCgroupDir(mount, root, cgroupPath string) (string, bool) {
	if !hasPathPrefix(cgroupPath, root) {
		return "", false
	}
	rel := "/"
	if root != "/" {
		rel = cgroupPath[len(root):]
		if rel == "" {
			rel = "/"
		}
	} else if cgroupPath != "/" {
		rel = cgroupPath
	}
	if strings.HasPrefix(rel, "/..") {
		return "", false
	}
	if rel == "/" {
		return path.Clean(mount), true
	}
	if !strings.HasPrefix(rel, "/") {
		rel = "/" + rel
	}
	return path.Clean(mount + rel), true
}

func hasPathPrefix(p, prefix string) bool {
	if prefix == "/" {
		return strings.HasPrefix(p, "/")
	}
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

func ancestorDirs(leaf, mount string) []string {
	leaf = path.Clean(leaf)
	mount = path.Clean(mount)
	if leaf == "." || leaf == "" {
		return nil
	}
	under := mount == "/" || leaf == mount || strings.HasPrefix(leaf, mount+"/")
	var dirs []string
	for {
		dirs = append(dirs, leaf)
		if !under || leaf == mount || leaf == "/" {
			break
		}
		next := path.Dir(leaf)
		if next == leaf {
			break
		}
		leaf = next
	}
	return dirs
}

func tightestQuota(dirs []string, version int, read func(dir string, version int) (int, int, bool, bool)) (cpus, dutyCap int, limited, readOK bool) {
	for _, dir := range dirs {
		c, cap, lim, ok := read(dir, version)
		if !ok {
			continue
		}
		readOK = true
		cpus, dutyCap, limited = tighterQuota(cpus, dutyCap, limited, c, cap, lim)
	}
	return
}

func tighterQuota(bestC, bestCap int, bestLimited bool, c, cap int, limited bool) (int, int, bool) {
	if !limited {
		return bestC, bestCap, bestLimited
	}
	if !bestLimited || quotaMilli(c, cap) < quotaMilli(bestC, bestCap) {
		return c, cap, true
	}
	return bestC, bestCap, bestLimited
}

func quotaMilli(cpus, dutyCap int) int {
	if cpus >= 1 {
		return cpus * 100
	}
	if dutyCap < 0 {
		return 0
	}
	return dutyCap
}

func parseStatCPUs(s string) []int {
	var ids []int
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if len(line) < 4 || !strings.HasPrefix(line, "cpu") || line[3] < '0' || line[3] > '9' {
			continue
		}
		end := 3
		for end < len(line) && line[end] >= '0' && line[end] <= '9' {
			end++
		}
		if end < len(line) && line[end] != ' ' && line[end] != '\t' {
			continue
		}
		id, err := strconv.Atoi(line[3:end])
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	return ids
}
