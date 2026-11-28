package service

import (
	"cmp"
	"slices"
	"time"

	"github.com/ReCasaOS/ReCasaOS-VulnScan/pkg/threat"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/pkg/trivy"
)

// AppSummary is what the dashboard shows of one app, or of one container made by hand.
type AppSummary struct {
	// App is the compose project, or the container's name when Loose.
	App   string
	Loose bool
	// Critical and High count a vulnerability of a package once, whatever the number of the
	// app's images that have it.
	Critical, High int
	// Exploited counts the vulnerabilities (critical or high) attackers already exploit, each
	// id once: as many as the alert says.
	Exploited int
	// EPSSMax is the highest probability of exploitation among its vulnerabilities; 0 when
	// none is known.
	EPSSMax float32
	// Actionable: a critical vulnerability, or a high one attackers exploit, and an update of
	// the app is offered. It is the one case the dashboard puts a badge on: there is something
	// to do.
	Actionable bool
	// OSOnly: the Java libraries of one of its images were not checked.
	OSOnly bool
	// ScannedAt is the oldest scan among its images; zero when none was scanned.
	ScannedAt time.Time
	// Skipped is why one of its images was not scanned; empty when all were.
	Skipped string
}

// owners are the names an image counts for: its apps, and its loose containers.
func owners(image Image) (names []string, loose []bool) {
	for _, name := range image.Apps {
		names, loose = append(names, name), append(loose, false)
	}
	for _, name := range image.Loose {
		names, loose = append(names, name), append(loose, true)
	}

	return names, loose
}

// exploited and score read the lists of exploited vulnerabilities, which may be nil.
func exploited(lists *threat.Lists, id string) bool { return lists != nil && lists.Exploited(id) }

func score(lists *threat.Lists, id string) (float32, bool) {
	if lists == nil {
		return 0, false
	}
	return lists.Score(id)
}

// Summaries is one entry per app and per loose container, sorted by name. updates says, by
// app, whether an update is offered; nil when that is not known. lists are the lists of
// exploited vulnerabilities in use; nil when there are none.
func Summaries(images []Image, state State, updates map[string]bool, lists *threat.Lists) []AppSummary {
	type key struct {
		name  string
		loose bool
	}
	summaries := map[key]*AppSummary{}
	seen := map[key]map[[2]string]bool{}
	exploitedIDs := map[key]map[string]bool{}
	exploitedHigh := map[key]bool{}

	for _, image := range images {
		result, scanned := state.Images[image.ID]
		names, loose := owners(image)
		for i, name := range names {
			k := key{name, loose[i]}
			summary := summaries[k]
			if summary == nil {
				summary = &AppSummary{App: name, Loose: loose[i]}
				summaries[k], seen[k], exploitedIDs[k] = summary, map[[2]string]bool{}, map[string]bool{}
			}
			if !scanned {
				continue
			}

			summary.OSOnly = summary.OSOnly || result.OSOnly
			if summary.Skipped == "" {
				summary.Skipped = result.Skipped
			}
			if !result.ScannedAt.IsZero() && (summary.ScannedAt.IsZero() || result.ScannedAt.Before(summary.ScannedAt)) {
				summary.ScannedAt = result.ScannedAt
			}
			for _, finding := range result.Findings {
				if s, known := score(lists, finding.ID); known && s > summary.EPSSMax {
					summary.EPSSMax = s
				}
				if exploited(lists, finding.ID) {
					if !exploitedIDs[k][finding.ID] {
						exploitedIDs[k][finding.ID] = true
						summary.Exploited++
					}
					exploitedHigh[k] = exploitedHigh[k] || finding.Severity != trivy.Critical
				}

				id := [2]string{finding.ID, finding.Package}
				if seen[k][id] {
					continue
				}
				seen[k][id] = true
				if finding.Severity == trivy.Critical {
					summary.Critical++
				} else {
					summary.High++
				}
			}
		}
	}

	list := make([]AppSummary, 0, len(summaries))
	for k, summary := range summaries {
		summary.Actionable = (summary.Critical > 0 || exploitedHigh[k]) && !k.loose && updates[k.name]
		list = append(list, *summary)
	}
	slices.SortFunc(list, func(a, b AppSummary) int {
		if c := cmp.Compare(a.App, b.App); c != 0 {
			return c
		}
		return cmp.Compare(btoi(a.Loose), btoi(b.Loose))
	})

	return list
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// uses says whether the app, or the loose container of that name, runs the image.
func (image Image) uses(name string) bool {
	return slices.Contains(image.Apps, name) || slices.Contains(image.Loose, name)
}

// Detail is the result of each image of an app (or of a loose container of that name), by
// image id; an image not scanned yet has an empty result. found is false when nothing on the
// box has that name.
func Detail(app string, images []Image, state State) (byImage map[string]ImageResult, found bool) {
	byImage = map[string]ImageResult{}
	for _, image := range images {
		if image.uses(app) {
			byImage[image.ID] = state.Images[image.ID]
		}
	}

	return byImage, len(byImage) > 0
}
