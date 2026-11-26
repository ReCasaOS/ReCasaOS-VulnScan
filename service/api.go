package service

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/ReCasaOS/ReCasaOS-VulnScan/codegen"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/pkg/trivy"
)

// updatesKept is how long the answer of app-management about the updates offered serves the
// routes: the dashboard asks for the apps on every paint.
const updatesKept = 5 * time.Minute

// API is what the routes serve, in the words of the API.
type API struct {
	Scanner *Scanner
	// DB is the date of the vulnerability database.
	DB func() (time.Time, error)
	// Ctx is the service's: a scan started by a request outlives the request.
	Ctx context.Context
	// Threat holds the lists of exploited vulnerabilities; nil when they are turned off.
	Threat *Threat

	mu        sync.Mutex
	updates   map[string]bool
	updatesAt time.Time
}

func timeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func (a *API) Status() codegen.Status {
	state, _ := a.Scanner.Snapshot()
	db, _ := a.DB()

	status := codegen.Status{Running: a.Scanner.Running(), LastRun: timeOrNil(state.LastRun), LastError: state.LastError, DbUpdatedAt: timeOrNil(db)}
	if a.Threat != nil {
		if l := a.Threat.Lists(); l != nil {
			status.ThreatUpdatedAt = timeOrNil(l.KEVDate)
		}
		status.ThreatError = a.Threat.LastError()
	}

	return status
}

func (a *API) Start() bool {
	return a.Scanner.Start(a.Ctx)
}

// offered is the updates offered, by app, as app-management last said them. When it does
// not answer nothing is offered: a badge says there is an update to install, and it must not
// be lit on a guess.
func (a *API) offered() map[string]bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if now := a.Scanner.Now(); a.updatesAt.IsZero() || now.Sub(a.updatesAt) >= updatesKept {
		ctx, cancel := context.WithTimeout(a.Ctx, 10*time.Second)
		defer cancel()
		a.updates, _ = a.Scanner.Updates(ctx)
		a.updatesAt = now
	}

	return a.updates
}

func (a *API) Apps() []codegen.AppSummary {
	state, images := a.Scanner.Snapshot()
	summaries := Summaries(images, state, a.offered())

	apps := make([]codegen.AppSummary, 0, len(summaries))
	for _, s := range summaries {
		apps = append(apps, codegen.AppSummary{
			App: s.App, Loose: s.Loose, Critical: s.Critical, High: s.High, Actionable: s.Actionable,
			OsOnly: s.OSOnly, ScannedAt: timeOrNil(s.ScannedAt), Skipped: s.Skipped,
		})
	}

	return apps
}

func (a *API) App(name string) (codegen.AppDetail, bool) {
	state, images := a.Scanner.Snapshot()
	byImage, found := Detail(name, images, state)
	if !found {
		return codegen.AppDetail{}, false
	}

	detail := codegen.AppDetail{App: name, Images: make([]codegen.ImageFindings, 0, len(byImage))}
	for id, result := range byImage {
		findings := make([]codegen.Finding, 0, len(result.Findings))
		for _, f := range result.Findings {
			findings = append(findings, codegen.Finding{
				Id: f.ID, Package: f.Package, Installed: f.Installed, Fixed: f.Fixed,
				Severity: severity(f.Severity), Title: f.Title, Url: f.URL,
			})
		}
		detail.Images = append(detail.Images, codegen.ImageFindings{
			ImageId: id, OsOnly: result.OSOnly, Skipped: result.Skipped, ScannedAt: timeOrNil(result.ScannedAt), Findings: findings,
		})
	}
	slices.SortFunc(detail.Images, func(x, y codegen.ImageFindings) int {
		if x.ImageId < y.ImageId {
			return -1
		}
		return 1
	})

	return detail, true
}

// Compare takes the request's context: a caller who hangs up stops the scan.
func (a *API) Compare(ctx context.Context, current, candidate string) codegen.Comparison {
	c := a.Scanner.Compare(ctx, current, candidate)

	added := make([]codegen.Finding, 0, len(c.Added))
	for _, f := range c.Added {
		added = append(added, codegen.Finding{
			Id: f.ID, Package: f.Package, Installed: f.Installed, Fixed: f.Fixed,
			Severity: severity(f.Severity), Title: f.Title, Url: f.URL,
		})
	}

	return codegen.Comparison{
		Verdict: codegen.ComparisonVerdict(c.Verdict), CurrentCritical: c.CurrentCritical,
		CandidateCritical: c.CandidateCritical, Added: added, Reason: c.Reason,
	}
}

func severity(s string) codegen.FindingSeverity {
	if s == trivy.Critical {
		return codegen.CRITICAL
	}
	return codegen.HIGH
}
