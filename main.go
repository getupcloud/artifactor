// Command artifactor discovers every container image running in a
// Kubernetes cluster (via the kubernetes.default.svc endpoint when running
// in-cluster), scans each one with syft (SBOM) and grype (CVE matching) used
// as embedded Go libraries, honoring the imagePullSecrets attached to pods
// and service accounts, and presents the results in a single-page web app.
package main

import (
	"context"
	_ "embed" // required for the go:embed directive below
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/getupcloud/artifactor/internal/api"
	"github.com/getupcloud/artifactor/internal/k8s"
	"github.com/getupcloud/artifactor/internal/scanner"
)

var version = "dev"

//go:embed web/index.html
var spaHTML []byte

func main() {
	var (
		port        = flag.Int("port", envInt("PORT", 8080), "HTTP listen port")
		namespace   = flag.String("namespace", os.Getenv("NAMESPACE"), "only scan pods in this namespace (empty = all namespaces)")
		interval    = flag.Duration("scan-interval", envDuration("SCAN_INTERVAL", 6*time.Hour), "automatic rescan interval (0 disables)")
		concurrency = flag.Int("concurrency", envInt("CONCURRENCY", 3), "number of parallel image scans")
		dbDir       = flag.String("db-dir", envStr("DB_DIR", defaultDBDir()), "grype vulnerability database directory")
		dbUpdate    = flag.Bool("db-auto-update", envBool("DB_AUTO_UPDATE", true), "download/update the grype vulnerability DB on startup")
		platform    = flag.String("platform", envStr("PLATFORM", "linux/"+runtime.GOARCH), "image platform to scan (e.g. linux/amd64)")
		scanTimeout = flag.Duration("scan-timeout", envDuration("SCAN_TIMEOUT", 15*time.Minute), "per-image scan timeout")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()
	log.SetPrefix("artifactor: ")
	log.SetFlags(log.LstdFlags)

	if *showVersion {
		fmt.Printf("artifactor %s\n", version)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 1. Kubernetes client: in-cluster (kubernetes.default.svc) or kubeconfig.
	k8sClient, mode, k8sErr := k8s.New()
	if k8sErr != nil {
		log.Printf("WARNING: %v (the web UI will show this error)", k8sErr)
	} else {
		log.Printf("kubernetes client ready (mode: %s)", mode)
	}

	// 2. Scanner + result store + HTTP API (served immediately; the
	//    vulnerability DB initializes in the background below).
	store := scanner.NewStore()
	var sc *scanner.Scanner
	if k8sClient != nil {
		sc = scanner.New(scanner.Options{
			Client:      k8sClient,
			Namespace:   *namespace,
			Platform:    *platform,
			Timeout:     *scanTimeout,
			Concurrency: *concurrency,
			Store:       store,
			Logger:      log.Default(),
		})
	}

	var dbMu sync.RWMutex
	dbStatus := scanner.DBStatus{Dir: *dbDir}
	server := api.New(api.Options{
		Store:   store,
		Scanner: sc,
		SPA:     spaHTML,
		Mode:    mode,
		K8sErr:  k8sErr,
		DB: func() scanner.DBStatus {
			dbMu.RLock()
			defer dbMu.RUnlock()
			return dbStatus
		},
	})

	httpServer := &http.Server{
		Addr:              ":" + strconv.Itoa(*port),
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("listening on http://0.0.0.0:%d (access with: kubectl port-forward ...)", *port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	// 3. Grype vulnerability database: downloads on first run (can take a
	//    while), so it runs in the background while the UI is already up.
	dbDone := make(chan struct{})
	go func() {
		defer close(dbDone)
		log.Printf("preparing grype vulnerability database at %s (first run downloads the DB) ...", *dbDir)
		provider, status, dbErr := scanner.NewProvider(*dbDir, version, *dbUpdate)
		dbMu.Lock()
		dbStatus = status
		dbMu.Unlock()
		if dbErr != nil {
			log.Printf("WARNING: vulnerability database: %v (scans will fail until it is available)", dbErr)
			if status.Error != "" {
				store.SetDBError(status.Error)
			}
			return
		}
		built := ""
		if status.Built != nil {
			built = ", built " + status.Built.Format(time.RFC3339)
		}
		log.Printf("vulnerability database ready (schema %s%s)", status.SchemaVersion, built)
		if sc != nil {
			sc.SetProvider(provider)
		}
	}()

	// 4. Scan loop: initial scan (after the DB attempt) + periodic rescans +
	//    shutdown handling.
	runScan := func() {
		if sc == nil {
			return
		}
		if !store.TryStartScan() {
			log.Print("scan already running, skipping trigger")
			return
		}
		go func() {
			defer store.FinishScan()
			if err := sc.RunOnce(ctx); err != nil && err != context.Canceled {
				log.Printf("scan run failed: %v", err)
				store.SetDBError(err.Error())
			}
		}()
	}
	if k8sErr == nil {
		go func() {
			<-dbDone
			runScan()
		}()
	}
	var ticker *time.Ticker
	var tickerCh <-chan time.Time
	if *interval > 0 {
		ticker = time.NewTicker(*interval)
		tickerCh = ticker.C
		defer ticker.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			log.Print("shutting down ...")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = httpServer.Shutdown(shutdownCtx)
			cancel()
			return
		case <-tickerCh:
			log.Printf("rescan interval (%s) elapsed", *interval)
			runScan()
		}
	}
}

func defaultDBDir() string {
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "artifactor", "db")
	}
	return "grype-db"
}

func envStr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
