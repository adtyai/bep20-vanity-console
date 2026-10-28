package job

import (
	"bytes"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"bep20-vanity-console/internal/config"
	"bep20-vanity-console/internal/store"
	"bep20-vanity-console/internal/vanity"
)

type GenerateFunc func() (privHex, checksum, lower string, err error)

type Logger func(event, rule string, id int64, count uint64, errorType string)

var shutdownLimit = 8 * time.Second

var saveOpenSegment = func(st *store.Store, accumulated time.Duration, segment time.Time) error {
	return st.SaveOpenSegment(accumulated, segment)
}

type Snapshot struct {
	Running   bool
	Exiting   bool
	Stoppable bool
	CPU       int
	Attempts  uint64
	PerSecond float64
	HaveSpeed bool
	Stuck     bool
	Runtime   time.Duration
	Rules     map[string]bool
	Observed  time.Duration
	SegmentOn bool
	Unsaved   int
	Broken    int
}

type hit struct {
	rule     string
	length   int
	checksum string
	lower    string
	privHex  string
	seq      uint64
}

type event struct {
	hit           *hit
	flushAttempts bool
	done          chan struct{}
}

type Runner struct {
	store *store.Store
	key   []byte
	gen   GenerateFunc
	logf  Logger

	cpu       atomic.Int32
	running   atomic.Bool
	exited    atomic.Bool
	abandoned atomic.Bool
	attempts  atomic.Uint64

	mu           sync.Mutex
	rules        map[string]bool
	accumulated  time.Duration
	segmentStart time.Time
	observedAt   time.Time

	sampleMu sync.Mutex
	samples  []sample

	workers int
	busy    []atomic.Int32

	events     chan event
	writerStop chan struct{}
	writerOnce sync.Once
	writerWG   sync.WaitGroup
	loopOnce   sync.Once

	stateMu      sync.Mutex
	persistMu    sync.Mutex
	pendingMu    sync.Mutex
	pending      []hit
	broken       atomic.Int32
	save         func([]byte, store.NewResult) (int64, error)
	hitSeq       atomic.Uint64
	cancelMu     sync.Mutex
	cancelled    map[string]uint64
	shutdownOnce sync.Once
}

type sample struct {
	at time.Time
	n  uint64
}

func New(st *store.Store, key []byte, gen GenerateFunc, workers int, logf Logger) *Runner {
	if gen == nil {
		gen = vanity.Generate
	}
	if workers < 1 {
		workers = runtime.NumCPU()
	}
	if logf == nil {
		logf = func(string, string, int64, uint64, string) {}
	}
	r := &Runner{
		store:      st,
		key:        key,
		gen:        gen,
		logf:       logf,
		rules:      map[string]bool{"8A": true, "9A": true, "1-8": true, "1-9": true},
		workers:    workers,
		busy:       make([]atomic.Int32, workers),
		events:     make(chan event, 1024),
		writerStop: make(chan struct{}),
		observedAt: time.Now(),
	}
	r.cpu.Store(50)
	return r
}

func SetLowPriority(logf Logger) {
	if logf == nil {
		logf = func(string, string, int64, uint64, string) {}
	}
	if err := setLowPriority(); err != nil {
		logf("error", "", 0, 0, "priority")
	}
}

func (r *Runner) Boot() error {
	st, err := r.store.Settings()
	if err != nil {
		return err
	}
	if err := config.ValidateCPU(st.CPU); err == nil {
		r.cpu.Store(int32(st.CPU))
	}
	r.mu.Lock()
	r.rules = copyRules(st.Rules)
	r.accumulated = st.Accumulated
	r.attempts.Store(st.Attempts)
	if st.Running {
		now := time.Now().UTC()
		r.segmentStart = now
		r.running.Store(true)
		acc := r.accumulated
		r.mu.Unlock()
		if err := r.store.SaveOpenSegment(acc, now); err != nil {
			return err
		}
	} else {
		r.mu.Unlock()
	}
	r.loopOnce.Do(func() {
		r.writerWG.Add(1)
		go r.writer()
		for i := 0; i < r.workers; i++ {
			go r.loop(i)
		}
		go r.sampler()
	})
	r.importPending()
	return nil
}

func (r *Runner) Start() error {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	if r.exited.Load() || r.running.Load() {
		return nil
	}
	now := time.Now().UTC()
	if err := r.store.MarkRunning(now); err != nil {
		return err
	}
	r.mu.Lock()
	r.segmentStart = now
	r.observedAt = time.Now()
	r.mu.Unlock()
	r.sampleMu.Lock()
	r.samples = nil
	r.sampleMu.Unlock()
	r.running.Store(true)
	return nil
}

func (r *Runner) Stop() error {
	r.stateMu.Lock()
	if r.exited.Load() {
		now := time.Now().UTC()
		err := r.store.MarkStopped(now)
		if err != nil {
			r.stateMu.Unlock()
			return err
		}
		r.running.Store(false)
		r.mu.Lock()
		r.segmentStart = time.Time{}
		r.mu.Unlock()
		r.stateMu.Unlock()
		return nil
	}
	if !r.running.Load() {
		r.stateMu.Unlock()
		return nil
	}
	now := time.Now().UTC()
	if err := r.store.MarkStopped(now); err != nil {
		r.stateMu.Unlock()
		return err
	}
	r.mu.Lock()
	if !r.segmentStart.IsZero() {
		d := now.Sub(r.segmentStart)
		if d > 0 {
			r.accumulated += d
		}
		r.segmentStart = time.Time{}
	}
	r.mu.Unlock()
	r.running.Store(false)
	r.stateMu.Unlock()
	r.waitIdle()
	r.syncFlush()
	return nil
}

func (r *Runner) Shutdown() {
	r.shutdownOnce.Do(func() {
		r.shutdownWithin(shutdownLimit)
	})
}

func (r *Runner) shutdownWithin(limit time.Duration) {
	done := make(chan struct{})
	go func() {
		r.stateMu.Lock()
		now := time.Now().UTC()
		if !r.abandoned.Load() {
			if err := r.checkpointLocked(now); err != nil {
				r.logf("error", "", 0, 0, "save")
			}
		}
		if !r.abandoned.Load() {
			if err := r.detachSegmentLocked(); err != nil {
				r.logf("error", "", 0, 0, "save")
			}
		}
		r.exited.Store(true)
		r.running.Store(false)
		r.stateMu.Unlock()
		r.waitIdle()
		if !r.abandoned.Load() {
			r.syncFlush()
		}
		r.writerOnce.Do(func() { close(r.writerStop) })
		if !r.abandoned.Load() {
			r.writerWG.Wait()
		}
		close(done)
	}()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		r.logf("error", "", 0, 0, "shutdown")
		r.abandonStore()
	}
}

func (r *Runner) abandonStore() {
	r.abandoned.Store(true)
	r.pendingMu.Lock()
	items := append([]hit(nil), r.pending...)
	r.pendingMu.Unlock()
	for _, h := range items {
		r.keepPending(h)
	}
}

func (r *Runner) SetCPU(n int) error {
	if err := config.ValidateCPU(n); err != nil {
		return err
	}
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	if err := r.store.SetCPU(n); err != nil {
		return err
	}
	r.cpu.Store(int32(n))
	return nil
}

func (r *Runner) SetRules(rules map[string]bool) error {
	next := copyRules(rules)
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	if err := r.store.SetRules(next); err != nil {
		return err
	}
	r.mu.Lock()
	r.rules = next
	r.mu.Unlock()
	return nil
}

func (r *Runner) HookSave(fn func([]byte, store.NewResult) (int64, error)) {
	r.pendingMu.Lock()
	r.save = fn
	r.pendingMu.Unlock()
}

func (r *Runner) EnqueueHit(rule string, length int, checksum, lower, priv string) {
	h := hit{rule: rule, length: length, checksum: checksum, lower: lower, privHex: priv}
	r.stamp(&h)
	r.events <- event{hit: &h}
	r.syncFlush()
}

func (r *Runner) Snapshot() Snapshot {
	r.mu.Lock()
	rules := copyRules(r.rules)
	acc := r.accumulated
	seg := r.segmentStart
	observed := time.Since(r.observedAt)
	r.mu.Unlock()
	running := r.running.Load()
	exiting := r.exited.Load()
	stoppable := running
	if exiting {
		stoppable = false
		if st, err := r.store.Settings(); err == nil {
			stoppable = st.Running
		}
	}
	runtime := acc
	if running && !seg.IsZero() {
		d := time.Since(seg)
		if d > 0 {
			runtime += d
		}
	}
	per, have, stuck := r.speed(time.Now(), running, observed)
	return Snapshot{
		Running:   running,
		Exiting:   exiting,
		Stoppable: stoppable,
		CPU:       int(r.cpu.Load()),
		Attempts:  r.attempts.Load(),
		PerSecond: per,
		HaveSpeed: have,
		Stuck:     stuck,
		Runtime:   runtime,
		Rules:     rules,
		Observed:  observed,
		SegmentOn: running,
		Unsaved:   r.unsaved(),
		Broken:    int(r.broken.Load()),
	}
}

func (r *Runner) loop(i int) {
	for {
		if r.exited.Load() {
			return
		}
		if !r.running.Load() {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		percent := int(r.cpu.Load())
		if percent < 5 {
			percent = 5
		}
		if percent > 95 {
			percent = 95
		}
		work := time.Duration(percent) * time.Millisecond
		rest := time.Duration(100-percent) * time.Millisecond
		end := time.Now().Add(work)
		for time.Now().Before(end) {
			if r.exited.Load() || !r.running.Load() {
				break
			}
			r.busy[i].Store(1)
			if r.exited.Load() || !r.running.Load() {
				r.busy[i].Store(0)
				break
			}
			r.oneKey()
			r.busy[i].Store(0)
		}
		if rest > 0 && r.running.Load() && !r.exited.Load() {
			time.Sleep(rest)
		}
	}
}

func (r *Runner) Key() []byte {
	return bytes.Clone(r.key)
}

func (r *Runner) oneKey() {
	priv, checksum, lower, err := r.gen()
	if err != nil {
		r.logf("error", "", 0, 0, "generate")
		time.Sleep(20 * time.Millisecond)
		return
	}
	r.attempts.Add(1)
	derived, derivedLower, err := vanity.AddressFromPrivateKeyHex(priv)
	if err != nil || derived != checksum || derivedLower != lower {
		r.logf("error", "", 0, 0, "address_mismatch")
		return
	}
	got, ok := vanity.EnabledMatch(derivedLower, r.enabled())
	if !ok {
		return
	}
	h := hit{
		rule:     got.Rule,
		length:   got.Length,
		checksum: derived,
		lower:    derivedLower,
		privHex:  priv,
	}
	r.stamp(&h)
	if r.abandoned.Load() {
		r.keepPending(h)
		return
	}
	r.events <- event{hit: &h}
}

func (r *Runner) enabled() map[string]bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return copyRules(r.rules)
}

func (r *Runner) writer() {
	defer r.writerWG.Done()
	for {
		select {
		case <-r.writerStop:
			r.drain()
			if !r.abandoned.Load() {
				_ = r.store.SetAttempts(r.attempts.Load())
			}
			return
		case ev := <-r.events:
			r.handle(ev)
		}
	}
}

func (r *Runner) handle(ev event) {
	if r.abandoned.Load() {
		if ev.hit != nil {
			r.keepPending(*ev.hit)
		}
		if ev.done != nil {
			close(ev.done)
		}
		return
	}
	if ev.hit != nil {
		r.persistHit(*ev.hit)
	}
	if r.abandoned.Load() {
		if ev.done != nil {
			close(ev.done)
		}
		return
	}
	if ev.flushAttempts || ev.done != nil {
		r.retryPending()
	}
	if ev.flushAttempts {
		if err := r.checkpoint(time.Now().UTC()); err != nil {
			r.logf("error", "", 0, 0, "save")
		}
		if !r.abandoned.Load() {
			if err := r.store.SetAttempts(r.attempts.Load()); err != nil {
				r.logf("error", "", 0, 0, "save")
			}
		}
	}
	if ev.done != nil {
		close(ev.done)
	}
}

func (r *Runner) persistHit(h hit) {
	r.persistMu.Lock()
	defer r.persistMu.Unlock()
	if r.stale(h) {
		return
	}
	if err := writePending(r.store.Dir(), r.key, h); err != nil {
		r.logf("error", h.rule, 0, 0, "pending")
	}
	if r.abandoned.Load() {
		r.remember(h)
		return
	}
	id, err := r.saveResult(store.NewResult{
		Rule: h.rule, Length: h.length, Checksum: h.checksum, Lower: h.lower, PrivHex: h.privHex,
	})
	if err == nil || alreadyStored(err) {
		r.forget(h.lower)
		if rmErr := removePending(r.store.Dir(), h.lower); rmErr != nil {
			r.logf("error", h.rule, id, 0, "pending")
		}
		if err == nil {
			r.logf("hit", h.rule, id, 1, "")
		}
		return
	}
	if r.remember(h) {
		r.logf("error", h.rule, 0, 0, "save")
	}
}

func (r *Runner) DeleteResult(id int64) error {
	rec, err := r.store.Get(id)
	if err != nil {
		return err
	}
	r.persistMu.Lock()
	defer r.persistMu.Unlock()
	r.cancel(rec.Lower)
	if err := removePending(r.store.Dir(), rec.Lower); err != nil {
		return err
	}
	r.forget(rec.Lower)
	err = r.store.Delete(id)
	if errors.Is(err, store.ErrScrub) {
		r.logf("error", "", id, 0, "scrub")
		return nil
	}
	return err
}

func (r *Runner) ClearBroken() (int, error) {
	r.persistMu.Lock()
	defer r.persistMu.Unlock()
	n, err := clearBroken(r.store.Dir(), r.key)
	_, broken, lerr := loadPending(r.store.Dir(), r.key)
	if lerr == nil {
		r.broken.Store(int32(broken))
	}
	return n, err
}

func (r *Runner) keepPending(h hit) {
	if r.stale(h) {
		return
	}
	if err := writePending(r.store.Dir(), r.key, h); err != nil {
		if r.stale(h) {
			return
		}
		r.logf("error", h.rule, 0, 0, "pending")
		r.remember(h)
		return
	}
	if r.stale(h) {
		if err := removePending(r.store.Dir(), h.lower); err != nil {
			r.logf("error", h.rule, 0, 0, "pending")
		}
		r.forget(h.lower)
	}
}

func (r *Runner) checkpoint(now time.Time) error {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	return r.checkpointLocked(now)
}

func (r *Runner) checkpointLocked(now time.Time) error {
	if r.abandoned.Load() {
		return nil
	}
	r.mu.Lock()
	if r.segmentStart.IsZero() {
		r.mu.Unlock()
		return nil
	}
	acc := r.accumulated
	d := now.Sub(r.segmentStart)
	if d > 0 {
		acc += d
	}
	r.accumulated = acc
	r.segmentStart = now
	r.mu.Unlock()
	if r.abandoned.Load() {
		return nil
	}
	return saveOpenSegment(r.store, acc, now)
}

func (r *Runner) detachSegmentLocked() error {
	r.mu.Lock()
	acc := r.accumulated
	r.segmentStart = time.Time{}
	r.mu.Unlock()
	if r.abandoned.Load() {
		return nil
	}
	return saveOpenSegment(r.store, acc, time.Time{})
}

func (r *Runner) saveResult(in store.NewResult) (int64, error) {
	r.pendingMu.Lock()
	fn := r.save
	r.pendingMu.Unlock()
	if fn != nil {
		return fn(r.key, in)
	}
	return r.store.SaveResult(r.key, in)
}

func (r *Runner) remember(h hit) bool {
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()
	for i := range r.pending {
		if r.pending[i].lower == h.lower {
			r.pending[i] = h
			return false
		}
	}
	r.pending = append(r.pending, h)
	return true
}

func (r *Runner) stamp(h *hit) {
	h.seq = r.hitSeq.Add(1)
}

func (r *Runner) cancel(lower string) {
	r.cancelMu.Lock()
	defer r.cancelMu.Unlock()
	if r.cancelled == nil {
		r.cancelled = make(map[string]uint64)
	}
	mark := r.hitSeq.Load()
	if old, ok := r.cancelled[lower]; ok && old > mark {
		mark = old
	}
	r.cancelled[lower] = mark
}

func (r *Runner) stale(h hit) bool {
	r.cancelMu.Lock()
	defer r.cancelMu.Unlock()
	mark, ok := r.cancelled[h.lower]
	return ok && h.seq <= mark
}

func (r *Runner) forget(lower string) {
	r.pendingMu.Lock()
	defer r.pendingMu.Unlock()
	out := r.pending[:0]
	for _, item := range r.pending {
		if item.lower != lower {
			out = append(out, item)
		}
	}
	r.pending = out
}

func (r *Runner) retryPending() {
	r.pendingMu.Lock()
	items := append([]hit(nil), r.pending...)
	r.pendingMu.Unlock()
	for _, item := range items {
		r.persistHit(item)
	}
}

func (r *Runner) unsaved() int {
	r.pendingMu.Lock()
	n := len(r.pending)
	r.pendingMu.Unlock()
	return n
}

func (r *Runner) importPending() {
	hits, broken, err := loadPending(r.store.Dir(), r.key)
	if broken > 0 {
		r.broken.Store(int32(broken))
		r.logf("error", "", 0, uint64(broken), "pending")
	}
	if err != nil {
		r.logf("error", "", 0, 0, "save")
	}
	for i := range hits {
		h := hits[i]
		r.stamp(&h)
		select {
		case r.events <- event{hit: &h}:
		default:
			r.remember(h)
		}
	}
}

func (r *Runner) drain() {
	for {
		select {
		case ev := <-r.events:
			r.handle(ev)
		default:
			return
		}
	}
}

func (r *Runner) syncFlush() {
	if r.abandoned.Load() {
		return
	}
	done := make(chan struct{})
	r.events <- event{flushAttempts: true, done: done}
	<-done
}

func (r *Runner) sampler() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		if r.exited.Load() {
			return
		}
		select {
		case <-t.C:
			r.record(time.Now())
			select {
			case r.events <- event{flushAttempts: true}:
			default:
			}
		case <-r.writerStop:
			return
		}
	}
}

func (r *Runner) record(now time.Time) {
	r.sampleMu.Lock()
	defer r.sampleMu.Unlock()
	r.samples = append(r.samples, sample{at: now, n: r.attempts.Load()})
	cutoff := now.Add(-20 * time.Second)
	i := 0
	for i < len(r.samples) && !r.samples[i].at.After(cutoff) {
		i++
	}
	if i > 0 {
		r.samples = append([]sample(nil), r.samples[i:]...)
	}
}

func (r *Runner) speed(now time.Time, running bool, observed time.Duration) (float64, bool, bool) {
	r.sampleMu.Lock()
	defer r.sampleMu.Unlock()
	if !running || len(r.samples) == 0 {
		return 0, false, false
	}
	latest := r.samples[len(r.samples)-1]
	var base *sample
	for i := range r.samples {
		if now.Sub(r.samples[i].at) >= 15*time.Second {
			s := r.samples[i]
			base = &s
		}
	}
	if base == nil {
		first := r.samples[0]
		dt := latest.at.Sub(first.at).Seconds()
		if dt >= 1 && latest.n >= first.n {
			return float64(latest.n-first.n) / dt, true, false
		}
		return 0, false, false
	}
	dt := latest.at.Sub(base.at).Seconds()
	if dt <= 0 {
		return 0, false, observed >= 15*time.Second
	}
	delta := float64(latest.n - base.n)
	if delta == 0 && observed >= 15*time.Second {
		return 0, true, true
	}
	return delta / dt, true, false
}

func (r *Runner) waitIdle() {
	for {
		idle := true
		for i := range r.busy {
			if r.busy[i].Load() != 0 {
				idle = false
				break
			}
		}
		if idle {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func copyRules(in map[string]bool) map[string]bool {
	return map[string]bool{
		"8A":  in["8A"],
		"9A":  in["9A"],
		"1-8": in["1-8"],
		"1-9": in["1-9"],
	}
}
