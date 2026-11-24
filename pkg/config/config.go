package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/ReCasaOS/CasaOS-Common/utils/constants"
	"github.com/ReCasaOS/ReCasaOS-VulnScan/common"
	"gopkg.in/ini.v1"
)

type CommonModel struct {
	RuntimePath string
}

type APPModel struct {
	LogPath     string
	LogSaveName string
	LogFileExt  string
	// StatePath holds the results of the scans. It is small.
	StatePath string
	// WorkPath holds Trivy's cache (its database is 1.7 GB) and the temporary copy of the image
	// being scanned. Empty puts it beside Docker's data, where the room is.
	WorkPath string
	// TrivyPath is the scanner the archive ships.
	TrivyPath string
}

var (
	ConfigFilePath = filepath.Join(constants.DefaultConfigPath, "vuln-scan.conf")

	CommonInfo = &CommonModel{
		RuntimePath: constants.DefaultRuntimePath,
	}

	AppInfo = &APPModel{
		LogPath:     constants.DefaultLogPath,
		LogSaveName: common.ServiceName,
		LogFileExt:  "log",
		StatePath:   "/var/lib/casaos-vuln-scan",
		TrivyPath:   "/usr/bin/casaos-trivy",
	}
)

func InitSetup(config string, sample string) {
	if len(config) > 0 {
		ConfigFilePath = config
	}

	// create default config file if not exist
	if _, err := os.Stat(ConfigFilePath); os.IsNotExist(err) {
		fmt.Println("config file not exist, create it")

		if err := os.WriteFile(ConfigFilePath, []byte(sample), 0o644); err != nil {
			panic(err)
		}
	}

	cfg, err := ini.LoadSources(ini.LoadOptions{Insensitive: true, AllowShadows: true}, ConfigFilePath)
	if err != nil {
		panic(err)
	}

	for section, v := range map[string]interface{}{"common": CommonInfo, "app": AppInfo} {
		if err := cfg.Section(section).MapTo(v); err != nil {
			log.Fatalf("Cfg.MapTo %s err: %v", section, err)
		}
	}
}
