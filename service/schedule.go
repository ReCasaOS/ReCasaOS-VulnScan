package service

import (
	"context"
	"time"
)

// NextRun is the next 05:30 on the box's clock after now: after the night's automatic app
// updates (02:00), the box's own update (03:00 to 05:00) and the Sunday cleanup (04:00).
func NextRun(now time.Time) time.Time {
	// time.Date and not Add(24h): the night the clocks change is not 24 hours long
	next := time.Date(now.Year(), now.Month(), now.Day(), 5, 30, 0, 0, now.Location())
	if !next.After(now) {
		next = time.Date(now.Year(), now.Month(), now.Day()+1, 5, 30, 0, 0, now.Location())
	}

	return next
}

// RunNightly scans every night at NextRun until ctx ends.
// shortcut: a night the box was off is not caught up, the next night scans; add a catch-up if owners ask
func (s *Scanner) RunNightly(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(NextRun(s.Now()))):
		}

		_ = s.Pass(ctx) // ErrRunning: a scan asked by hand runs, which is tonight's
	}
}
