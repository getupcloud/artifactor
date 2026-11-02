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

// DBOptions configures the preparation of the grype vulnerability database.
type DBOptions struct {
	Root       string // directory that holds the DB (DBRootDir)
	AppVersion string // version string sent in the User-Agent header
	CACert     string // path to a PEM CA certificate used to verify the DB server ("" = system roots)
	AutoUpdate bool   // download/update the DB when it is missing or outdated
	// DirectDownload fetches the listing (latest.json) and the DB archive
	// directly with net/http, instead of using the grype download library.
	// Insecure controls TLS verification for that download.
	DirectDownload bool
	Insecure       bool // skip TLS certificate verification for the direct DB download
}

// DBStatus describes the state of the grype vulnerability database.
type DBStatus struct {
	Dir           string     `json:"dir"`
	Built         *time.Time `json:"built,omitempty"`
	SchemaVersion string     `json:"schemaVersion,omitempty"`
	Error         string     `json:"error,omitempty"`
}

// newCurator builds the grype DB curator for dbRoot, configured so that a
// stale database is preferred over no database and updates come from the
// default anchore distribution endpoint. A non-empty caCert (path to a PEM
// file) is used to verify the download server instead of the system roots.
func newCurator(dbRoot, appVersion, caCert string) (dbv6.Curator, error) {
	installGrypeLogger() // show the DB download/update progress via logx

	cfg := installation.DefaultConfig(clio.Identification{Name: "artifactor", Version: appVersion})
	cfg.DBRootDir = dbRoot
	cfg.ValidateAge = false // a stale DB is better than no DB
	cfg.MaxAllowedBuiltAge = 90 * 24 * time.Hour

	clientCfg := distribution.DefaultConfig()
	clientCfg.ID = clio.Identification{Name: "artifactor", Version: appVersion}
	clientCfg.CACert = caCert
	client, err := distribution.NewClient(clientCfg)
	if err != nil {
		return nil, fmt.Errorf("create db client: %w", err)
	}
	return installation.NewCurator(cfg, client)
}

// NewProvider prepares the grype vulnerability database at opts.Root and
// returns a vulnerability provider backed by it. With AutoUpdate enabled the
// latest database is downloaded when missing or when an update check is due;
// an existing database is still used if the update fails (e.g. no network).
func NewProvider(opts DBOptions) (vulnerability.Provider, DBStatus, error) {
	status := DBStatus{Dir: opts.Root}

	curator, err := newCurator(opts.Root, opts.AppVersion, opts.CACert)
	if err != nil {
		return nil, status, fmt.Errorf("create db curator: %w", err)
	}

	if opts.AutoUpdate {
		var updateErr error
		if opts.DirectDownload {
			_, updateErr = directUpdate(opts)
		} else {
			_, updateErr = curator.Update()
		}
		if updateErr != nil {
			status.Error = fmt.Sprintf("db update: %v", updateErr)
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

// RefreshDB checks for and applies a grype vulnerability DB update in place,
// returning a fresh provider backed by the (possibly updated) database. The
// provider is non-nil only when a usable DB is available afterwards; on
// failure callers should keep their previous provider.
func RefreshDB(opts DBOptions) (updated bool, provider vulnerability.Provider, status DBStatus, err error) {
	status = DBStatus{Dir: opts.Root}

	curator, err := newCurator(opts.Root, opts.AppVersion, opts.CACert)
	if err != nil {
		return false, nil, status, fmt.Errorf("create db curator: %w", err)
	}

	if opts.DirectDownload {
		updated, err = directUpdate(opts)
	} else {
		updated, err = curator.Update()
	}
	if err != nil {
		status.Error = fmt.Sprintf("db update: %v", err)
		return updated, nil, status, err
	}

	reader, err := curator.Reader()
	if err != nil {
		if status.Error == "" {
			status.Error = err.Error()
		}
		return updated, nil, status, fmt.Errorf("open vulnerability database: %w", err)
	}
	if meta, err := reader.GetDBMetadata(); err == nil {
		status.Built = meta.BuildTimestamp
		status.SchemaVersion = fmt.Sprintf("%d.%d.%d", meta.Model, meta.Revision, meta.Addition)
	}

	return updated, dbv6.NewVulnerabilityProvider(reader), status, nil
}
