package service

import (
	"testing"
	"time"
)

func TestNextRunBefore(t *testing.T) {
	got := NextRun(time.Date(2026, 11, 24, 3, 0, 0, 0, time.UTC))
	if want := time.Date(2026, 11, 24, 5, 30, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("%v, want %v", got, want)
	}
}

func TestNextRunAfter(t *testing.T) {
	want := time.Date(2026, 11, 25, 5, 30, 0, 0, time.UTC)
	for _, now := range []time.Time{
		time.Date(2026, 11, 24, 5, 30, 0, 0, time.UTC), // on the dot: tonight's is this one, the next is tomorrow's
		time.Date(2026, 11, 24, 18, 0, 0, 0, time.UTC),
	} {
		if got := NextRun(now); !got.Equal(want) {
			t.Errorf("%v: %v, want %v", now, got, want)
		}
	}
}

// The night the clocks change has 23 or 25 hours: the scan is at 05:30 on the box's clock.
func TestNextRunDST(t *testing.T) {
	paris, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Skip("no time zone database here")
	}
	for _, day := range []time.Time{
		time.Date(2026, 3, 28, 18, 0, 0, 0, paris),  // the clocks go forward on the 29th
		time.Date(2026, 10, 24, 18, 0, 0, 0, paris), // and back on the 25th
	} {
		got := NextRun(day)
		if got.Hour() != 5 || got.Minute() != 30 || got.Day() != day.Day()+1 || got.Location() != paris {
			t.Errorf("%v: %v, want 05:30 the next day in Paris", day, got)
		}
	}
}
