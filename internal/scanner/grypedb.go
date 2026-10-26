package scanner

import (
	"fmt"
	"time"

	"github.com/anchore/clio"
	dbv6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/vulnerability"
)

// DBStatus describes the state of the grype vulnerability database.
type DBStatus struct {
	Dir           string     `json:"dir"`
	Built         *time.Time `json:"built,omitempty"`
	SchemaVersion string     `json:"schemaVersion,omitempty"`
	Error         string     `json:"error,omitempty"`
}

// NewProvider prepares the grype vulnerability database at dbRoot and returns
// a vulnerability provider backed by it. With autoUpdate enabled the latest
// database is downloaded when missing or when an update check is due; an
// existing database is still used if the update fails (e.g. no network).
func NewProvider(dbRoot, appVersion string, autoUpdate bool) (vulnerability.Provider, DBStatus, error) {
	status := DBStatus{Dir: dbRoot}

	cfg := installation.DefaultConfig(clio.Identification{Name: "artifactor", Version: appVersion})
	cfg.DBRootDir = dbRoot
	cfg.ValidateAge = false // a stale DB is better than no DB
	cfg.MaxAllowedBuiltAge = 90 * 24 * time.Hour

	clientCfg := distribution.DefaultConfig()
	clientCfg.ID = clio.Identification{Name: "artifactor", Version: appVersion}
	client, err := distribution.NewClient(clientCfg)
	if err != nil {
		return nil, status, fmt.Errorf("create db client: %w", err)
	}
	curator, err := installation.NewCurator(cfg, client)
	if err != nil {
		return nil, status, fmt.Errorf("create db curator: %w", err)
	}

	if autoUpdate {
		if _, err := curator.Update(); err != nil {
			status.Error = fmt.Sprintf("db update: %v", err)
		}
	}

	reader, err := curator.Reader()
	if err != nil {
		if status.Error == "" {
			status.Error = err.Error()
		}
		return nil, status, fmt.Errorf("open vulnerability database (enable network or set --db-auto-update=false with an existing DB): %w", err)
	}
	if meta, err := reader.GetDBMetadata(); err == nil {
		status.Built = meta.BuildTimestamp
		status.SchemaVersion = fmt.Sprintf("%d.%d.%d", meta.Model, meta.Revision, meta.Addition)
	}

	return dbv6.NewVulnerabilityProvider(reader), status, nil
}
