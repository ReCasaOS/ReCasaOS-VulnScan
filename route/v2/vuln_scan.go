package v2

import (
	"context"
	"errors"
	"net/http"

	"github.com/ReCasaOS/ReCasaOS-VulnScan/codegen"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/service"
	"github.com/labstack/echo/v4"
)

// Scans is what the routes read and start.
type Scans interface {
	Status() codegen.Status
	Apps() []codegen.AppSummary
	// App is false for an app no container of the box belongs to.
	App(name string) (codegen.AppDetail, bool)
	// Start starts a scan in the background; false when one already runs.
	Start() bool
	// StartApp starts a scan of one app's images in the background: service.ErrNoApp for
	// an app no container of the box belongs to, service.ErrRunning when a scan already runs.
	StartApp(name string) error
	// Compare scans both images if need be and says whether the candidate is worse.
	Compare(ctx context.Context, current, candidate string) codegen.Comparison
}

type VulnScan struct {
	scans Scans
}

func NewVulnScan(scans Scans) codegen.ServerInterface {
	return &VulnScan{scans: scans}
}

func message(ctx echo.Context, status int, text string) error {
	return ctx.JSON(status, codegen.BaseResponse{Message: &text})
}

func (v *VulnScan) GetStatus(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, codegen.StatusOK{Data: v.scans.Status()})
}

func (v *VulnScan) GetApps(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, codegen.AppsOK{Data: v.scans.Apps()})
}

func (v *VulnScan) GetApp(ctx echo.Context, app string) error {
	detail, found := v.scans.App(app)
	if !found {
		return message(ctx, http.StatusNotFound, "no app of that name on this box")
	}

	return ctx.JSON(http.StatusOK, codegen.AppOK{Data: detail})
}

func (v *VulnScan) StartScan(ctx echo.Context) error {
	if !v.scans.Start() {
		return message(ctx, http.StatusConflict, "a scan is already running")
	}

	return message(ctx, http.StatusAccepted, "scan started")
}

func (v *VulnScan) StartAppScan(ctx echo.Context, app string) error {
	switch err := v.scans.StartApp(app); {
	case errors.Is(err, service.ErrNoApp):
		return message(ctx, http.StatusNotFound, "no app of that name on this box")
	case errors.Is(err, service.ErrRunning):
		return message(ctx, http.StatusConflict, "a scan is already running")
	case err != nil:
		return message(ctx, http.StatusInternalServerError, err.Error())
	}

	return message(ctx, http.StatusAccepted, "scan started")
}

func (v *VulnScan) CompareImages(ctx echo.Context) error {
	var body codegen.CompareImagesJSONRequestBody
	if err := ctx.Bind(&body); err != nil {
		return message(ctx, http.StatusBadRequest, "the body is not what the API expects")
	}

	return ctx.JSON(http.StatusOK, codegen.CompareOK{Data: v.scans.Compare(ctx.Request().Context(), body.Current, body.Candidate)})
}
