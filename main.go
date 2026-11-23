//go:generate bash -c "mkdir -p codegen && go run github.com/deepmap/oapi-codegen/cmd/oapi-codegen@v1.12.4 -generate types,server,spec -package codegen api/vuln_scan/openapi.yaml > codegen/vuln_scan_api.go"

package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ReCasaOS/CasaOS-Common/external"
	"github.com/ReCasaOS/CasaOS-Common/model"
	"github.com/ReCasaOS/CasaOS-Common/utils/file"
	"github.com/ReCasaOS/CasaOS-Common/utils/logger"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/common"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/pkg/config"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/pkg/trivy"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/route"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/service"
	"github.com/coreos/go-systemd/daemon"
	"go.uber.org/zap"

	util_http "github.com/ReCasaOS/CasaOS-Common/utils/http"
)

var (
	commit = "private build"
	date   = "private build"

	//go:embed api/index.html
	_docHTML string

	//go:embed api/vuln_scan/openapi.yaml
	_docYAML string

	//go:embed build/sysroot/etc/casaos/vuln-scan.conf.sample
	_confSample string
)

const dockerSocket = "/var/run/docker.sock"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// parse arguments and intialize
	{
		configFlag := flag.String("c", "", "config file path")
		versionFlag := flag.Bool("v", false, "version")

		flag.Parse()

		if *versionFlag {
			fmt.Printf("v%s\n", common.Version)
			os.Exit(0)
		}

		println("git commit:", commit)
		println("build date:", date)

		config.InitSetup(*configFlag, _confSample)

		logger.LogInit(config.AppInfo.LogPath, config.AppInfo.LogSaveName, config.AppInfo.LogFileExt)
	}

	events := service.Events{RuntimePath: config.CommonInfo.RuntimePath}
	if err := events.Register(ctx); err != nil {
		logger.Error("error when trying to register the event type - the alerts of the scans will not be discoverable", zap.Error(err))
	}

	scanner, runner := newScanner(ctx, events)
	api := &service.API{Scanner: scanner, DB: runner.DBUpdatedAt, Ctx: ctx}

	// setup listener
	listener, err := net.Listen("tcp", net.JoinHostPort(common.Localhost, "0"))
	if err != nil {
		panic(err)
	}

	urlFilePath := filepath.Join(config.CommonInfo.RuntimePath, "vuln-scan.url")
	if err := file.CreateFileAndWriteContent(urlFilePath, "http://"+listener.Addr().String()); err != nil {
		logger.Error("error when creating address file", zap.Error(err),
			zap.Any("address", listener.Addr().String()),
			zap.Any("filepath", urlFilePath),
		)
	}

	// initialize routers and register at gateway
	{
		gateway, err := external.NewManagementService(config.CommonInfo.RuntimePath)
		if err != nil {
			panic(err)
		}

		for _, apiPath := range []string{route.V2APIPath, route.V2DocPath} {
			if err := gateway.CreateRoute(&model.Route{
				Path:   apiPath,
				Target: "http://" + listener.Addr().String(),
			}); err != nil {
				panic(err)
			}
		}
	}

	mux := &util_http.HandlerMultiplexer{
		HandlerMap: map[string]http.Handler{
			"v2":  route.InitV2Router(api),
			"doc": route.InitV2DocRouter(_docHTML, _docYAML),
		},
	}

	nightly := make(chan struct{})
	go func() {
		defer close(nightly)
		scanner.RunNightly(ctx)
	}()

	// notify systemd that we are ready
	{
		if supported, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
			logger.Error("Failed to notify systemd that vulnerability scan service is ready", zap.Any("error", err))
		} else if supported {
			logger.Info("Notified systemd that vulnerability scan service is ready")
		} else {
			logger.Info("This process is not running as a systemd service.")
		}

		logger.Info("Vulnerability scan service is listening...", zap.Any("address", listener.Addr().String()))
	}

	s := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second, // fix G112: Potential slowloris attack (see https://github.com/securego/gosec)
	}

	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.Shutdown(shutdownCtx); err != nil {
			logger.Error("error when shutting down the http server", zap.Error(err))
		}
	}()

	err = s.Serve(listener) // not using http.serve() to fix G114: Use of net/http serve function that has no support for setting timeouts (see https://github.com/securego/gosec)
	if err != nil && err != http.ErrServerClosed {
		panic(err)
	}

	cancel()
	<-nightly
}

// newScanner wires the scanner to the box: Docker's socket, the Trivy the archive ships, and
// app-management. The work folder (Trivy's cache and its temporary copies) goes beside
// Docker's data unless the configuration names one; when Docker does not answer at start it
// falls back to the state folder, and the next start tries again.
func newScanner(ctx context.Context, events service.Events) (*service.Scanner, trivy.Runner) {
	docker := service.NewDockerSocket(dockerSocket)

	work := config.AppInfo.WorkPath
	if work == "" {
		rootCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		root, err := docker.RootDir(rootCtx)
		cancel()
		if err != nil {
			logger.Error("docker does not say where its data is, the scans work in the state folder", zap.Error(err))
			work = config.AppInfo.StatePath
		} else {
			work = config.WorkDir(root)
		}
	}

	cache, tmp := filepath.Join(work, "cache"), filepath.Join(work, "tmp")
	for _, dir := range []string{cache, tmp} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			logger.Error("error when creating a work folder", zap.String("dir", dir), zap.Error(err))
		}
	}

	runner := trivy.Runner{Bin: config.AppInfo.TrivyPath, CacheDir: cache, TempDir: tmp, Timeout: 20 * time.Minute}
	appManagement := service.AppManagement{RuntimePath: config.CommonInfo.RuntimePath}

	return &service.Scanner{
		Docker: docker, Trivy: runner, Busy: appManagement.Busy, Updates: appManagement.Updates,
		Free: service.FreeBytes, Publish: events.Publish, Now: time.Now,
		Dir: config.AppInfo.StatePath, Tmp: tmp,
	}, runner
}
