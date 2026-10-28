package httpapi

import (
	"fmt"
	"time"

	"bep20-vanity-console/internal/job"
	"bep20-vanity-console/internal/vanity"
)

func speedText(snap job.Snapshot) string {
	if !snap.Running {
		return "未运行"
	}
	if snap.Stuck || (snap.HaveSpeed && snap.PerSecond <= 0) {
		return "卡住"
	}
	if !snap.HaveSpeed {
		return "估算中"
	}
	return fmt.Sprintf("每秒 %.0f 个", snap.PerSecond)
}

func etaText(rule string, snap job.Snapshot) string {
	if !snap.Rules[rule] {
		return "已关闭"
	}
	if snap.Stuck || (snap.Running && snap.HaveSpeed && snap.PerSecond <= 0) {
		return "卡住"
	}
	if !snap.Running || !snap.HaveSpeed || snap.PerSecond <= 0 {
		return "估算中"
	}
	seconds := vanity.ExpectedAttempts(rule) / snap.PerSecond
	if seconds < 0 || seconds > 60*60*24*365*100 {
		return "估算中"
	}
	return "约 " + roughDuration(time.Duration(seconds*float64(time.Second)))
}

func roughDuration(d time.Duration) string {
	if d < time.Second {
		return "1 秒"
	}
	if d < time.Minute {
		return fmt.Sprintf("%d 秒", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d 分钟", int(d.Minutes()))
	}
	if d < 48*time.Hour {
		return fmt.Sprintf("%d 小时", int(d.Hours()))
	}
	return fmt.Sprintf("%d 天", int(d.Hours()/24))
}

func runtimeText(d time.Duration) string {
	if d < time.Second {
		return "不到 1 秒"
	}
	d = d.Truncate(time.Second)
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	hours := d / time.Hour
	d -= hours * time.Hour
	mins := d / time.Minute
	secs := (d % time.Minute) / time.Second
	if days > 0 {
		return fmt.Sprintf("%d 天 %d 小时 %d 分", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%d 小时 %d 分", hours, mins)
	}
	if mins > 0 {
		return fmt.Sprintf("%d 分 %d 秒", mins, secs)
	}
	return fmt.Sprintf("%d 秒", secs)
}

func formatShanghai(t time.Time, loc *time.Location) string {
	if t.IsZero() {
		return "尚无"
	}
	return t.In(loc).Format("2006-01-02 15:04:05")
}
