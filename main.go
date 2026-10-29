// Command artifactor discovers every container image running in a
// Kubernetes cluster (via the kubernetes.default.svc endpoint when running
// in-cluster), scans each one with syft (SBOM) and grype (CVE matching) used
// as embedded Go libraries, honoring the imagePullSecrets attached to pods
// and service accounts, and presents the results in a single-page web app.
package main

import (
	"context"
	_ "embed" // required for the go:embed directive below
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	flag "github.com/spf13/pflag" // flags defined and displayed with --

	"github.com/getupcloud/artifactor/internal/api"
	"github.com/getupcloud/artifactor/internal/ecr"
	"github.com/getupcloud/artifactor/internal/k8s"
	"github.com/getupcloud/artifactor/internal/scanner"
)

var version = "dev"

//go:embed web/index.html
var spaHTML []byte

//go:embed web/names.json
var namesJSON []byte

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install", "uninstall":
			runInstallCmd(os.Args[1], os.Args[2:])
			return
		case "scan":
			runScanCmd(os.Args[2:])
			return
		case "--version", "-v":
			fmt.Printf("artifactor %s\n", version)
			return
		}
		if strings.HasPrefix(os.Args[1], "-") {
			// flags given without a subcommand: treat as `scan`
			// (backward compatibility with the previous default)
			runScanCmd(os.Args[1:])
			return
		}
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		printMainUsage()
		os.Exit(2)
	}
	printMainUsage()
}

// printMainUsage prints the top-level subcommand help.
func printMainUsage() {
	fmt.Fprintf(os.Stderr, "Usage: artifactor [install|uninstall|scan] [flags]\n\n"+
		"Subcommands:\n"+
		"  scan         scan the cluster images and serve the web app\n"+
		"  install      deploy the manifests to the cluster via kubectl (--dump prints them instead)\n"+
		"  uninstall    remove the manifests from the cluster via kubectl (--dump prints them instead)\n\n"+
		"Run 'artifactor scan --help' for the scan flags.\n")
}

// runScanCmd implements the `scan` subcommand (the previous default
// behavior): scan the cluster and serve the SPA + API.
func runScanCmd(args []string) {
	fs := flag.NewFlagSet("artifactor scan", flag.ExitOnError)
	var (
		port         = fs.Int("port", envInt("PORT", 8080), "HTTP listen port")
		namespaceCSV = fs.String("namespace", os.Getenv("NAMESPACE"), "only scan pods in these namespaces (comma-separated list; empty = all namespaces)")
		interval     = fs.Duration("scan-interval", envDuration("SCAN_INTERVAL", 0), "automatic rescan interval (0 disables)")
		concurrency  = fs.Int("concurrency", envInt("CONCURRENCY", 3), "number of parallel image scans")
		dbDir        = fs.String("db-dir", envStr("DB_DIR", defaultDBDir()), "grype vulnerability database directory")
		dbUpdate     = fs.Bool("db-auto-update", envBool("DB_AUTO_UPDATE", true), "download/update the grype vulnerability DB on startup")
		fromSBOM     = fs.String("from-sbom", envStr("FROM_SBOM", ""), "scan an SBOM file or all files of a directory (non-recursive) with grype only, skipping syft and image download")
		dbRefresh    = fs.Duration("db-refresh-interval", envDuration("DB_REFRESH_INTERVAL", 24*time.Hour), "check for grype DB updates on this interval while running (0 disables)")
		platform     = fs.String("platform", envStr("PLATFORM", "linux/"+runtime.GOARCH), "image platform to scan (e.g. linux/amd64)")
		scanTimeout  = fs.Duration("scan-timeout", envDuration("SCAN_TIMEOUT", 15*time.Minute), "per-image scan timeout")
		exportHTML   = fs.String("export-html", envStr("EXPORT_HTML", ""), "run a scan, export the report as a single self-contained HTML file to this path, and exit")
		exportSBOM   = fs.String("export-sbom", envStr("EXPORT_SBOM", ""), "run a scan, export one syft SBOM (syft-json) per image into this directory, and exit")
		exportGrype  = fs.String("export-grype", envStr("EXPORT_GRYPE", ""), "run a scan, export one grype JSON report per image into this directory, and exit")
		exportAll    = fs.String("export", envStr("EXPORT", ""), "run a scan, export the full report (scan.html + sbom/ + grype/) into this directory, and exit")
		exportCSV    = fs.String("export-csv", envStr("EXPORT_CSV", ""), "run a scan, export the CVE report as CSV to this file, and exit")
		openReport   = fs.String("open", envStr("OPEN", ""), "open the exported scan.html with this command after --export (default \"xdg-open\"; ${FILE} is replaced by the path)")
		ecrAuth      = fs.Bool("ecr-auth", envBool("ECR_AUTH", true), "authenticate to AWS ECR registries via the AWS credential chain (IRSA) when no pull secret matches")
		keepSBOM     = fs.Bool("keep-sbom", envBool("KEEP_SBOM", true), "keep the syft SBOM of each image in memory (needed by --export-sbom; disable to save memory)")
		insecure     = fs.Bool("insecure-skip-tls", envBool("INSECURE_SKIP_TLS", false), "skip TLS certificate verification for remote servers (image registries and the vulnerability-name refresh)")
		customerName = fs.String("customer-name", os.Getenv("CUSTOMER_NAME"), "customer name shown in the execution logs and report title")
		clusterName  = fs.String("cluster-name", os.Getenv("CLUSTER_NAME"), "cluster name shown in the execution logs and report title")
		showVersion  = fs.Bool("version", false, "print version and exit")
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: artifactor scan [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	fs.Lookup("open").NoOptDefVal = "xdg-open"
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	log.SetPrefix("artifactor: ")
	log.SetFlags(log.LstdFlags)

	if *showVersion {
		fmt.Printf("artifactor %s\n", version)
		return
	}

	if *customerName != "" || *clusterName != "" {
		log.Printf("customer: %q, cluster: %q", *customerName, *clusterName)
	}

	namespaces := splitNamespaces(*namespaceCSV)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *exportHTML != "" || *exportSBOM != "" || *exportGrype != "" || *exportAll != "" || *exportCSV != "" {
		err := runExport(ctx, exportRequest{
			htmlPath: *exportHTML,
			sbomDir:  *exportSBOM,
			grypeDir: *exportGrype,
			allDir:   *exportAll,
			csvPath:  *exportCSV,
		}, *dbDir, *dbUpdate, *fromSBOM, namespaces, *platform, *scanTimeout, *concurrency, *ecrAuth, *keepSBOM, *insecure, *customerName, *clusterName, *openReport)
		if err != nil {
			log.Fatalf("export: %v", err)
		}
		return
	}

	// 1. Kubernetes client: in-cluster (kubernetes.default.svc) or kubeconfig.
	//    With --from-sbom no cluster access is needed: syft and the image
	//    download are skipped, only the local SBOM file(s) are scanned.
	var k8sClient *k8s.Client
	mode, k8sErr := "from-sbom", error(nil)
	if *fromSBOM == "" {
		k8sClient, mode, k8sErr = k8s.New()
		if k8sErr != nil {
			log.Printf("WARNING: %v (the web UI will show this error)", k8sErr)
		} else {
			log.Printf("kubernetes client ready (mode: %s)", mode)
		}
	} else {
		log.Printf("SBOM input mode: %s (kubernetes client skipped)", *fromSBOM)
	}

	// 2. Scanner + result store + HTTP API (served immediately; the
	//    vulnerability DB initializes in the background below).
	store := scanner.NewStore()
	var ecrProvider *ecr.Provider
	if *ecrAuth {
		ecrProvider = ecr.NewProvider()
	}
	var sc *scanner.Scanner
	if k8sClient != nil || *fromSBOM != "" {
		sc = scanner.New(scanner.Options{
			Client:      k8sClient,
			Namespaces:  namespaces,
			FromSBOM:    *fromSBOM,
			ECR:         ecrProvider,
			KeepSBOM:    *keepSBOM,
			Insecure:    *insecure,
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
		Store:        store,
		Scanner:      sc,
		SPA:          spaHTML,
		NamesJSON:    namesJSON,
		Mode:         mode,
		K8sErr:       k8sErr,
		Insecure:     *insecure,
		CustomerName: *customerName,
		ClusterName:  *clusterName,
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

	// Refresh the named vulnerabilities list from the GitHub repository at
	// startup (10s timeout); the embedded copy stays as fallback.
	go func() {
		if err := server.FetchNamedVulns(ctx); err != nil {
			log.Printf("WARNING: cannot refresh named vulnerabilities from GitHub: %v (using the embedded copy)", err)
		} else {
			log.Print("named vulnerabilities refreshed from GitHub")
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

	// 3b. Periodic DB refresh: while the server runs, re-check for a newer
	//     grype DB on --db-refresh-interval and swap the provider in place.
	go func() {
		<-dbDone // never touch the DB dir while the initial download runs
		if *dbRefresh <= 0 {
			return
		}
		t := time.NewTicker(*dbRefresh)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				log.Print("checking for vulnerability DB update ...")
				updated, provider, status, err := scanner.RefreshDB(*dbDir, version)
				if err != nil {
					// keep the current (still usable) DB; just log the failure
					log.Printf("WARNING: vulnerability DB refresh failed: %v", err)
					continue
				}
				dbMu.Lock()
				dbStatus = status
				dbMu.Unlock()
				if sc != nil && provider != nil {
					sc.SetProvider(provider)
				}
				if updated {
					log.Printf("vulnerability DB updated (schema %s)", status.SchemaVersion)
				} else {
					log.Print("vulnerability DB already up to date")
				}
			}
		}
	}()

	// 4. Scan loop: scans only start on demand (the "Scan now" button posts
	//    to /api/scan) or via an explicitly configured --scan-interval.
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

// exportRequest holds the destinations of the --export* one-shot flags.
type exportRequest struct {
	htmlPath string // --export-html: single self-contained HTML file
	sbomDir  string // --export-sbom: directory for per-image syft SBOMs
	grypeDir string // --export-grype: directory for per-image grype JSON reports
	allDir   string // --export: directory with scan.html + sbom/ + grype/
	csvPath  string // --export-csv: CVE report as CSV
}

// runExport implements the --export* flags: prepare the DB, scan every image
// once, write the requested artifacts, and exit.
func runExport(ctx context.Context, req exportRequest, dbDir string, dbUpdate bool, fromSBOM string, namespaces []string, platform string, scanTimeout time.Duration, concurrency int, ecrAuth, keepSBOM, insecure bool, customerName, clusterName, openCmd string) error {
	var k8sClient *k8s.Client
	mode := "from-sbom"
	if fromSBOM == "" {
		var k8sErr error
		k8sClient, mode, k8sErr = k8s.New()
		if k8sErr != nil {
			return fmt.Errorf("no cluster access: %w", k8sErr)
		}
		log.Printf("kubernetes client ready (mode: %s)", mode)
	} else {
		log.Printf("SBOM input mode: %s (kubernetes client skipped)", fromSBOM)
	}

	log.Printf("preparing grype vulnerability database at %s ...", dbDir)
	provider, dbStatus, dbErr := scanner.NewProvider(dbDir, version, dbUpdate)
	if dbErr != nil {
		log.Printf("WARNING: vulnerability database: %v (images will be scanned but CVE matching will fail)", dbErr)
	}

	store := scanner.NewStore()
	if dbStatus.Error != "" {
		store.SetDBError(dbStatus.Error)
	}
	var ecrProvider *ecr.Provider
	if ecrAuth {
		ecrProvider = ecr.NewProvider()
	}
	// SBOM exports need the SBOM retained in memory; force it on when the
	// user asked for sbom/complete exports.
	if (req.sbomDir != "" || req.allDir != "") && !keepSBOM {
		log.Print("WARNING: --keep-sbom=false but an SBOM export was requested; forcing SBOM retention for this run")
		keepSBOM = true
	}
	sc := scanner.New(scanner.Options{
		Client:      k8sClient,
		Namespaces:  namespaces,
		FromSBOM:    fromSBOM,
		Provider:    provider,
		ECR:         ecrProvider,
		KeepSBOM:    keepSBOM,
		Insecure:    insecure,
		Platform:    platform,
		Timeout:     scanTimeout,
		Concurrency: concurrency,
		Store:       store,
		Logger:      log.Default(),
	})

	if fromSBOM != "" {
		log.Print("scanning SBOM file(s) with grype ...")
	} else {
		log.Print("scanning all cluster images ...")
	}
	if err := sc.RunOnce(ctx); err != nil && err != context.Canceled {
		return err
	}

	server := api.New(api.Options{
		Store:        store,
		SPA:          spaHTML,
		NamesJSON:    namesJSON,
		Mode:         mode,
		Insecure:     insecure,
		CustomerName: customerName,
		ClusterName:  clusterName,
		DB:           func() scanner.DBStatus { return dbStatus },
	})

	// refresh the named vulnerabilities list (10s timeout); the embedded
	// copy is used when the fetch fails
	if err := server.FetchNamedVulns(ctx); err != nil {
		log.Printf("WARNING: cannot refresh named vulnerabilities from GitHub: %v (using the embedded copy)", err)
	}

	if req.htmlPath != "" {
		if err := os.WriteFile(req.htmlPath, server.ExportHTML(), 0o644); err != nil {
			return err
		}
		log.Printf("HTML report exported to %s", req.htmlPath)
	}
	if req.sbomDir != "" {
		n, err := server.ExportSBOMs(req.sbomDir)
		if err != nil {
			return err
		}
		log.Printf("%d SBOM(s) exported to %s", n, req.sbomDir)
	}
	if req.grypeDir != "" {
		n, err := server.ExportGrype(req.grypeDir)
		if err != nil {
			return err
		}
		log.Printf("%d grype report(s) exported to %s", n, req.grypeDir)
	}
	if req.allDir != "" {
		htmlPath, csvPath, sbomCount, grypeCount, err := server.ExportAll(req.allDir)
		if err != nil {
			return err
		}
		log.Printf("full report exported to %s (%s, %s, %d SBOM(s), %d grype report(s))", req.allDir, htmlPath, csvPath, sbomCount, grypeCount)
		if openCmd != "" {
			if err := openFile(openCmd, htmlPath); err != nil {
				log.Printf("WARNING: cannot open %s: %v", htmlPath, err)
			}
		}
	} else if openCmd != "" {
		log.Print("WARNING: --open requires --export <dir> (there is no scan.html to open)")
	}
	if req.csvPath != "" {
		if err := server.ExportCVEsCSV(req.csvPath); err != nil {
			return err
		}
		log.Printf("CSV report exported to %s", req.csvPath)
	}
	return nil
}

// openFile launches the viewer command for a file. ${FILE} in the command is
// replaced with the file path; otherwise the path is appended as the last
// argument.
func openFile(command, file string) error {
	cmdStr := strings.ReplaceAll(command, "${FILE}", file)
	parts := strings.Fields(cmdStr)
	if len(parts) == 0 {
		return fmt.Errorf("empty open command")
	}
	args := parts[1:]
	if !strings.Contains(command, "${FILE}") {
		args = append(args, file)
	}
	cmd := exec.Command(parts[0], args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Start()
}

// splitNamespaces parses a comma-separated namespace list, trimming spaces,
// dropping empties and duplicates.
func splitNamespaces(csv string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, dup := seen[part]; dup {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	return out
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
