package service

import (
	"context"
	"slices"
	"strings"

	"github.com/ReCasaOS/ReCasaOS-VulnScan/pkg/trivy"
)

const (
	VerdictWorse    = "worse"
	VerdictNotWorse = "not_worse"
	VerdictUnknown  = "unknown"
)

// Comparison says whether an image is worse than the one it would replace.
type Comparison struct {
	Verdict                            string
	CurrentCritical, CandidateCritical int
	// Added are the critical vulnerabilities of the candidate that the current image does not
	// have, by id, sorted.
	Added []trivy.Finding
	// Reason is set when the verdict is unknown.
	Reason string
}

func unknown(reason string) Comparison { return Comparison{Verdict: VerdictUnknown, Reason: reason} }

// critical is the critical findings of a scan, one per id, sorted by id.
func critical(result ImageResult) []trivy.Finding {
	var found []trivy.Finding
	for _, f := range result.Findings {
		if f.Severity == trivy.Critical {
			found = append(found, f)
		}
	}
	slices.SortStableFunc(found, func(a, b trivy.Finding) int { return strings.Compare(a.ID, b.ID) })

	return slices.CompactFunc(found, func(a, b trivy.Finding) bool { return a.ID == b.ID })
}

// Compare scans both images and says whether the candidate has more critical vulnerabilities
// than the current one. It keeps nothing: what Pass found, and the file it saves, are
// untouched. The candidate is scanned first, and the current image in the mode the candidate
// ended up in, so that the two counts are of the same things.
func (s *Scanner) Compare(ctx context.Context, current, candidate string) Comparison {
	switch {
	case current == "" || candidate == "":
		return unknown("an image to compare is not named")
	case current == candidate:
		return Comparison{Verdict: VerdictNotWorse}
	}

	result := s.compare(ctx, current, candidate)
	if ctx.Err() != nil {
		// a scan that was stopped leaves its copy of the image behind; ctx is over, the cleaning is not
		_, _ = s.emptyTmp(context.Background())
	}

	return result
}

func (s *Scanner) compare(ctx context.Context, current, candidate string) Comparison {
	tmp, err := s.TmpDir(ctx)
	if err != nil {
		return unknown(err.Error())
	}
	size, err := s.Docker.ImageSize(ctx, candidate)
	if err != nil {
		return unknown(err.Error())
	}
	need := uint64(max(size, 0)) + roomMargin
	if db, err := s.Trivy.DBUpdatedAt(); err != nil || db.IsZero() {
		need += roomDatabase
	}
	if free, err := s.Free(tmp); err == nil && free < need {
		return unknown(SkippedNoRoom)
	}

	cand, err := s.scanOne(ctx, candidate, false)
	if err != nil {
		return unknown(err.Error())
	}
	cur, err := s.scanOne(ctx, current, cand.OSOnly)
	if err != nil {
		return unknown(err.Error())
	}
	if cur.OSOnly && !cand.OSOnly {
		if cand, err = s.scanOne(ctx, candidate, true); err != nil {
			return unknown(err.Error())
		}
	}

	have := map[string]bool{}
	for _, f := range critical(cur) {
		have[f.ID] = true
	}
	now := critical(cand)
	got := Comparison{Verdict: VerdictNotWorse, CurrentCritical: len(have), CandidateCritical: len(now)}
	for _, f := range now {
		if !have[f.ID] {
			got.Added = append(got.Added, f)
		}
	}
	if got.CandidateCritical > got.CurrentCritical {
		got.Verdict = VerdictWorse
	}

	return got
}
