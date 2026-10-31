package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	k8sscheme "k8s.io/client-go/kubernetes/scheme"

	"github.com/getupcloud/artifactor/internal/k8s"
	"github.com/getupcloud/artifactor/internal/logx"
)

// Constants of the in-cluster scan (`artifactor scan --in-cluster`): the
// resources live in the standard artifactor namespace. The report and the DB
// live under /data (the emptyDir, writable by the pod's uid 65532 — the
// container root filesystem is not); the report is packed as a .tar.gz in the
// same volume, from where the local process downloads it via the Kubernetes
// API.
const (
	inClusterNamespace = "artifactor"
	inClusterPodName   = "artifactor-scan"
	inClusterContainer = "scan"
	podReportDir       = "/data/report"
	podReportTar       = "/data/report.tar.gz"
	podDBDir           = "/data/db"
)

// inClusterOpts carries the resolved scan flags into the in-cluster runner.
type inClusterOpts struct {
	Force           bool
	Image           string
	ImagePullPolicy string
	Namespaces      []string
	Concurrency     int
	DBAutoUpdate    bool
	DBCACert        string
	DBDirect        bool
	IgnoreDB        bool
	Platform        string
	ScanTimeout     time.Duration
	ECRAuth         bool
	KeepSBOM        bool
	Insecure        bool
	CustomerName    string
	ClusterName     string
	LogLevel        string
	FromSBOM        string
	ExportHTML      string
	ExportSBOM      string
	ExportGrype     string
	ExportAll       string
	ExportCSV       string
	OpenCmd         string
	OpenShift       bool
}

var deploymentImageExtractPattern = regexp.MustCompile(`(?m)^\s+image:\s*(\S+)`)

var manifestDecoder = serializer.NewCodecFactory(k8sscheme.Scheme).UniversalDeserializer()

// runInClusterScan executes the scan inside the cluster in a temporary pod
// (`artifactor scan --in-cluster`): it creates the pod (plus the shared
// namespace/SA/RBAC manifests and, when --db-ca-cert is given, a ConfigMap
// with the CA), waits for the pod to finish, downloads the report .tar.gz via
// the Kubernetes API, extracts it into the local --export directory, and
// removes the pod + ConfigMap (asking first, unless --in-cluster-force).
func runInClusterScan(ctx context.Context, o inClusterOpts) error {
	if o.ExportAll == "" {
		return fmt.Errorf("--in-cluster requires --export <dir> (the report is downloaded as a .tar.gz)")
	}
	if o.FromSBOM != "" {
		return fmt.Errorf("--from-sbom cannot be used with --in-cluster (the SBOM file(s) are local)")
	}
	if o.ExportHTML != "" || o.ExportSBOM != "" || o.ExportGrype != "" || o.ExportCSV != "" {
		return fmt.Errorf("--in-cluster only supports --export <dir> (the other --export* flags write locally)")
	}

	kc, mode, err := k8s.New()
	if err != nil {
		return err
	}
	logx.Infof("kubernetes client ready (mode: %s)", mode)

	infraObjs, err := decodeInfraManifests()
	if err != nil {
		return err
	}

	// CA ConfigMap (the CA file is copied into the pod via the Kubernetes
	// API when --db-ca-cert is provided).
	var caCM *corev1.ConfigMap
	if o.DBCACert != "" {
		pemBytes, err := os.ReadFile(o.DBCACert)
		if err != nil {
			return fmt.Errorf("read --db-ca-cert: %w", err)
		}
		data, err := manifestsFS.ReadFile("deploy/" + dbcaTemplateName)
		if err != nil {
			return err
		}
		data = bytes.ReplaceAll(data, []byte(caBundlePlaceholder), indentPEM(strings.TrimSpace(string(pemBytes))))
		obj, err := decodeManifest(data)
		if err != nil {
			return err
		}
		cm, ok := obj.(*corev1.ConfigMap)
		if !ok {
			return fmt.Errorf("unexpected %T for %s", obj, dbcaTemplateName)
		}
		caCM = cm
	}

	image := o.Image
	if image == "" {
		image = deploymentImage()
		if image == "" {
			return fmt.Errorf("no image found in the deployment manifest; set --in-cluster-image")
		}
	}

	pod := buildScanPod(image, o, caCM != nil)

	// Leftover resources from a previous run: ask before overwriting
	// (--in-cluster-force overwrites and removes without asking).
	_, podExists, err := kc.GetPod(ctx, inClusterNamespace, inClusterPodName)
	if err != nil {
		return err
	}
	cmExists := false
	if caCM != nil {
		cmExists, err = kc.ObjectExists(ctx, caCM)
		if err != nil {
			return err
		}
	}
	overwrite := o.Force
	if (podExists || cmExists) && !o.Force {
		if !askYN("In-cluster scan resources already exist (pod " + inClusterPodName + " and/or CA ConfigMap). Overwrite them?") {
			return fmt.Errorf("aborted: existing in-cluster scan resources found (use --in-cluster-force to overwrite)")
		}
		overwrite = true
	}

	// Shared infrastructure: created when missing, reused otherwise.
	for i, obj := range infraObjs {
		kind := []string{"namespace", "serviceaccount", "clusterrole", "clusterrolebinding"}[i]
		existed, err := kc.ApplyObject(ctx, obj, false)
		if err != nil {
			return err
		}
		if existed {
			logx.Debugf("reusing existing %s", kind)
		} else {
			logx.Infof("created %s", kind)
		}
	}
	// OpenShift: the SCC + RBAC that let the scan pod run as uid/gid 65532
	// (the same manifests `artifactor install --openshift` applies).
	if o.OpenShift {
		osObjs, err := decodeOpenshiftManifests()
		if err != nil {
			return err
		}
		for _, obj := range osObjs {
			existed, err := kc.ApplyObject(ctx, obj, false)
			if err != nil {
				return err
			}
			label := objectLabel(obj)
			if existed {
				logx.Debugf("reusing existing %s", label)
			} else {
				logx.Infof("created %s", label)
			}
		}
	}
	if caCM != nil {
		existed, err := kc.ApplyObject(ctx, caCM, overwrite)
		if err != nil {
			return err
		}
		if existed {
			logx.Infof("CA ConfigMap %s ready", caCM.Name)
		} else {
			logx.Infof("created CA ConfigMap %s", caCM.Name)
		}
	}

	if podExists {
		if err := kc.DeletePod(ctx, inClusterNamespace, inClusterPodName); err != nil {
			return err
		}
		if err := waitPodGone(ctx, kc); err != nil {
			return err
		}
	}
	if err := kc.CreatePod(ctx, pod); err != nil {
		return fmt.Errorf("create scan pod: %w", err)
	}
	logx.Infof("in-cluster scan pod %s/%s created (image %s); %d flag(s) forwarded", inClusterNamespace, inClusterPodName, image, len(pod.Spec.Containers[0].Args)-1)
	applied := true

	// Remove the pod + CA ConfigMap at the end (asking first unless forced).
	defer func() {
		if !applied {
			return
		}
		remove := o.Force
		if !remove {
			remove = askYN("Remove the in-cluster scan resources from the cluster (pod " + inClusterPodName + " and CA ConfigMap)?")
		}
		cleanCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if remove {
			if err := kc.DeletePod(cleanCtx, inClusterNamespace, inClusterPodName); err != nil {
				logx.Warnf("remove scan pod: %v", err)
			}
			if caCM != nil {
				if err := kc.DeleteObject(cleanCtx, caCM); err != nil {
					logx.Warnf("remove CA ConfigMap: %v", err)
				}
			}
			logx.Infof("in-cluster scan resources removed")
		} else {
			logx.Infof("in-cluster scan resources kept (pod %s/%s)", inClusterNamespace, inClusterPodName)
		}
	}()

	// The pod container holds after the export (--hold), so the download
	// polls the exec until the tarball appears (it is written atomically).
	// The same poll loop prints the pod logs (stdout + stderr merged by the
	// container runtime) to the local stderr as they are produced: regular
	// short GETs with SinceTime — reliable in any environment, unlike a
	// long-held follow stream.
	lw := &podLogWriter{w: os.Stderr}
	localTar := strings.TrimRight(o.ExportAll, "/") + ".tar.gz"
	if dir := filepath.Dir(localTar); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	if err := downloadReport(ctx, kc, localTar, lw); err != nil {
		showPodLogs(ctx, kc, lw) // show the remaining pod log lines
		return fmt.Errorf("in-cluster scan failed: %w", err)
	}
	showPodLogs(ctx, kc, lw) // catch the trailing lines (export done; holding ...)
	logx.Infof("report downloaded to %s", localTar)

	if err := tarGzExtract(localTar, o.ExportAll); err != nil {
		return fmt.Errorf("extract report: %w", err)
	}
	logx.Infof("report extracted to %s", o.ExportAll)

	// --open: open the downloaded scan.html locally (the same behavior as a
	// local --export run)
	if o.OpenCmd != "" {
		htmlPath := filepath.Join(o.ExportAll, "scan.html")
		if err := openFile(o.OpenCmd, htmlPath); err != nil {
			logx.Warnf("cannot open %s: %v", htmlPath, err)
		}
	}
	return nil
}

// decodeInfraManifests decodes the embedded namespace/serviceaccount/
// clusterrole/clusterrolebinding manifests (the same resources `artifactor
// install` deploys).
func decodeInfraManifests() ([]runtime.Object, error) {
	var objs []runtime.Object
	for _, name := range []string{"namespace.yaml", "serviceaccount.yaml", "clusterrole.yaml", "clusterrolebinding.yaml"} {
		data, err := manifestsFS.ReadFile("deploy/" + name)
		if err != nil {
			return nil, err
		}
		obj, err := decodeManifest(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		objs = append(objs, obj)
	}
	return objs, nil
}

// decodeManifest decodes a single Kubernetes YAML manifest into a typed
// object.
func decodeManifest(data []byte) (runtime.Object, error) {
	obj, _, err := manifestDecoder.Decode(data, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	return obj, nil
}

// decodeOpenshiftManifests decodes the embedded OpenShift SCC + RBAC
// manifests (deploy/openshift.yaml.tmpl).
func decodeOpenshiftManifests() ([]runtime.Object, error) {
	data, err := manifestsFS.ReadFile("deploy/" + openshiftTemplateName)
	if err != nil {
		return nil, err
	}
	return decodeManifestDocs(data)
}

// decodeManifestDocs decodes every YAML document of a multi-document
// manifest, preferring typed objects and falling back to unstructured for
// kinds not registered in the client scheme (SecurityContextConstraints).
func decodeManifestDocs(data []byte) ([]runtime.Object, error) {
	var objs []runtime.Object
	for _, doc := range bytes.Split(data, []byte("\n---\n")) {
		if len(bytes.TrimSpace(doc)) == 0 {
			continue
		}
		obj, _, err := manifestDecoder.Decode(doc, nil, nil)
		if err != nil {
			typedErr := err
			obj, _, err = manifestDecoder.Decode(doc, nil, &unstructured.Unstructured{})
			if err != nil {
				return nil, fmt.Errorf("decode manifest document: %w", typedErr)
			}
		}
		objs = append(objs, obj)
	}
	return objs, nil
}

// objectLabel renders "<kind> <name>" for an applied object (used in logs).
func objectLabel(obj runtime.Object) string {
	if meta, ok := obj.(metav1.Object); ok {
		kind := obj.GetObjectKind().GroupVersionKind().Kind
		if kind == "" {
			kind = fmt.Sprintf("%T", obj)
		}
		return strings.ToLower(kind) + " " + meta.GetName()
	}
	return fmt.Sprintf("%T", obj)
}

// deploymentImage extracts the container image of the embedded deployment
// manifest (the image used by `artifactor install`).
func deploymentImage() string {
	data, err := manifestsFS.ReadFile("deploy/deployment.yaml")
	if err != nil {
		return ""
	}
	m := deploymentImageExtractPattern.FindSubmatch(data)
	if len(m) == 2 {
		return string(m[1])
	}
	return ""
}

// buildScanPod builds the one-shot scan pod. The container runs the same
// `artifactor scan` flags the user provided (minus the --in-cluster* flags),
// with --export and --db-dir rewritten to pod-local paths, plus the internal
// --export-tar flag that produces the .tar.gz downloaded afterwards.
func buildScanPod(image string, o inClusterOpts, withCA bool) *corev1.Pod {
	pullPolicy := corev1.PullIfNotPresent
	if o.ImagePullPolicy != "" {
		pullPolicy = corev1.PullPolicy(o.ImagePullPolicy)
	}
	container := corev1.Container{
		Name:            inClusterContainer,
		Image:           image,
		ImagePullPolicy: pullPolicy,
		Args:            scanPodArgs(o),
		VolumeMounts: []corev1.VolumeMount{
			{Name: "data", MountPath: "/data"},
		},
		// same hardening as the artifactor deployment (also required by the
		// OpenShift artifactor SCC)
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: boolPtr(false),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("256Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("2"),
				corev1.ResourceMemory: resource.MustParse("4Gi"),
			},
		},
	}
	volumes := []corev1.Volume{
		{Name: "data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	}
	if withCA {
		container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{
			Name: "db-ca", MountPath: dbCaCertMountDir, ReadOnly: true,
		})
		volumes = append(volumes, corev1.Volume{
			Name: "db-ca",
			VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: "artifactor-db-ca"},
			}},
		})
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      inClusterPodName,
			Namespace: inClusterNamespace,
			Labels:    map[string]string{"app.kubernetes.io/name": "artifactor-scan"},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "artifactor",
			RestartPolicy:      corev1.RestartPolicyNever,
			// same security settings as the artifactor deployment: uid 65532
			// and fsGroup 65532 so the emptyDir volumes are writable
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: boolPtr(true),
				RunAsUser:    int64Ptr(65532),
				FSGroup:      int64Ptr(65532),
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			},
			ImagePullSecrets: []corev1.LocalObjectReference{{Name: "artifactor-docker-image-token"}},
			Containers:       []corev1.Container{container},
			Volumes:          volumes,
		},
	}
}

// scanPodArgs builds the `artifactor scan` arguments for the pod container
// from the resolved local flags.
func scanPodArgs(o inClusterOpts) []string {
	args := []string{
		"scan",
		"--export=" + podReportDir,
		"--export-tar=" + podReportTar,
		"--hold",
		"--db-dir=" + podDBDir,
		"--db-auto-update=" + strconv.FormatBool(o.DBAutoUpdate),
		"--concurrency=" + strconv.Itoa(o.Concurrency),
		"--platform=" + o.Platform,
		"--scan-timeout=" + o.ScanTimeout.String(),
		"--keep-sbom=" + strconv.FormatBool(o.KeepSBOM),
		"--ecr-auth=" + strconv.FormatBool(o.ECRAuth),
		"--log-level=" + o.LogLevel,
	}
	if o.Insecure {
		args = append(args, "--insecure-skip-tls")
	}
	if o.DBDirect {
		args = append(args, "--grype-db-direct-download")
	}
	if o.IgnoreDB {
		args = append(args, "--ignore-grype-db-unavailable")
	}
	if len(o.Namespaces) > 0 {
		args = append(args, "--namespace="+strings.Join(o.Namespaces, ","))
	}
	if o.CustomerName != "" {
		args = append(args, "--customer-name="+o.CustomerName)
	}
	if o.ClusterName != "" {
		args = append(args, "--cluster-name="+o.ClusterName)
	}
	if o.DBCACert != "" {
		args = append(args, "--db-ca-cert="+dbCaCertMountPath)
	}
	return args
}

// podLogWriter forwards a pod log stream to w, tracking how many bytes were
// forwarded and the timestamp of the last complete line (the pod binary logs
// through logx, so every line carries a "YYYY/MM/DD HH:MM:SS" timestamp).
// The timestamp lets a re-attached stream resume instead of repeating the
// whole log.
type podLogWriter struct {
	w        io.Writer
	bytes    int64
	rest     []byte
	lastTime *metav1.Time
}

func (p *podLogWriter) Write(b []byte) (int, error) {
	// forward everything immediately (real-time display)
	if _, err := p.w.Write(b); err != nil {
		return 0, err
	}
	p.bytes += int64(len(b))
	data := append(p.rest, b...)
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			break
		}
		p.recordLine(data[:i+1])
		data = data[i+1:]
	}
	p.rest = append(p.rest[:0], data...)
	return len(b), nil
}

// recordLine extracts the logx timestamp of a complete log line, if present.
func (p *podLogWriter) recordLine(line []byte) {
	// "artifactor: 2006/01/02 15:04:05 ..." -> timestamp at [12:31)
	if len(line) >= 31 {
		if t, err := time.Parse("2006/01/02 15:04:05", string(line[12:31])); err == nil {
			p.lastTime = &metav1.Time{Time: t}
		}
	}
}

// since returns the timestamp to resume the log stream from (nil = from the
// beginning).
func (p *podLogWriter) since() *metav1.Time {
	return p.lastTime
}

// downloadReport polls the scan pod (exec `artifactor cat`) until the report
// tarball appears and streams it into localTar. The pod container keeps
// running after the export (--hold), so the exec stays available; the
// tarball is written atomically inside the pod, so its appearance means the
// archive is complete. Each poll also prints the new pod log lines (lw).
func downloadReport(ctx context.Context, kc *k8s.Client, localTar string, lw *podLogWriter) error {
	phase := ""
	waiting := true
	for {
		showPodLogs(ctx, kc, lw)

		f, err := os.Create(localTar)
		if err != nil {
			return fmt.Errorf("create %s: %w", localTar, err)
		}
		err = kc.CopyPodFile(ctx, inClusterNamespace, inClusterPodName, inClusterContainer, podReportTar, f, io.Discard)
		closeErr := f.Close()
		if err == nil && closeErr == nil {
			if fi, statErr := os.Stat(localTar); statErr == nil && fi.Size() > 0 {
				return nil
			}
		}

		// Not ready yet (or the pod failed): inspect the pod before retrying.
		pod, found, gerr := kc.GetPod(ctx, inClusterNamespace, inClusterPodName)
		if gerr != nil {
			return gerr
		}
		if !found {
			return fmt.Errorf("scan pod %s disappeared", inClusterPodName)
		}
		if p := string(pod.Status.Phase); p != phase {
			logx.Infof("scan pod status: %s", pod.Status.Phase)
			phase = p
		}
		switch pod.Status.Phase {
		case corev1.PodFailed:
			return fmt.Errorf("scan pod failed")
		case corev1.PodSucceeded:
			return fmt.Errorf("scan pod finished before the report could be downloaded (pod image without --hold support?)")
		}
		if waiting {
			logx.Infof("waiting for the report to be ready inside the pod ...")
			waiting = false
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// showPodLogs fetches the pod logs produced after the last shown line and
// prints them through lw (which tracks the last timestamp shown).
func showPodLogs(ctx context.Context, kc *k8s.Client, lw *podLogWriter) {
	since := lw.since()
	if since != nil {
		// second-granular timestamps: start after the last shown second to
		// avoid repeating lines
		since = &metav1.Time{Time: since.Add(time.Second)}
	}
	logs, err := kc.PodLogs(ctx, inClusterNamespace, inClusterPodName, inClusterContainer, since)
	if err != nil {
		logx.Debugf("pod logs poll: %v", err)
		return
	}
	if logs != "" {
		if _, err := lw.Write([]byte(logs)); err != nil {
			logx.Debugf("print pod logs: %v", err)
		}
	}
}

// waitPodGone waits until the scan pod has been fully removed (up to 60s).
func waitPodGone(ctx context.Context, kc *k8s.Client) error {
	deadline := time.Now().Add(60 * time.Second)
	for {
		_, found, err := kc.GetPod(ctx, inClusterNamespace, inClusterPodName)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for pod %s to be removed", inClusterPodName)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// askYN asks a yes/no question on stderr and reads the answer from stdin.
// The default (on empty input or EOF) is "no".
func askYN(prompt string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N]: ", prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		fmt.Fprintln(os.Stderr)
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// tarGzDir creates dest as a gzipped tar archive of the regular files in
// srcDir (relative paths, directories excluded). The archive is written to a
// temporary file and renamed into place, so dest only appears once the
// archive is complete (the in-cluster download polls for its existence).
func tarGzDir(srcDir, dest string) error {
	srcAbs, err := filepath.Abs(srcDir)
	if err != nil {
		return err
	}
	destAbs, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	if strings.HasPrefix(destAbs, srcAbs+string(filepath.Separator)) {
		return fmt.Errorf("archive destination %s is inside the source directory %s", dest, srcDir)
	}

	part := dest + ".part"
	f, err := os.Create(part)
	if err != nil {
		return fmt.Errorf("create %s: %w", part, err)
	}
	fail := func(err error) error {
		f.Close()
		os.Remove(part)
		return err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	err = filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tw, in)
		closeErr := in.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err != nil {
		return fail(fmt.Errorf("archive %s: %w", srcDir, err))
	}
	if err := tw.Close(); err != nil {
		return fail(err)
	}
	if err := gz.Close(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(part)
		return err
	}
	if err := os.Rename(part, dest); err != nil {
		os.Remove(part)
		return fmt.Errorf("rename %s -> %s: %w", part, dest, err)
	}
	return nil
}

// tarGzExtract extracts a gzipped tar archive into destDir. Only regular
// files and directories are extracted; symlinks and hard links are skipped
// and path traversal outside destDir is rejected.
func tarGzExtract(src, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open gzip stream: %w", err)
	}
	defer gz.Close()

	root, err := os.OpenRoot(destDir)
	if err != nil {
		return err
	}
	defer root.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		name := filepath.Clean(hdr.Name)
		if !filepath.IsLocal(name) || filepath.IsAbs(name) {
			return fmt.Errorf("unsafe path in report archive: %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.Mkdir(name, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
		case tar.TypeReg:
			if dir := filepath.Dir(name); dir != "." {
				if err := root.MkdirAll(dir, 0o755); err != nil {
					return err
				}
			}
			out, err := root.Create(name)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, tr)
			closeErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}
}

func boolPtr(v bool) *bool    { return &v }
func int64Ptr(v int64) *int64 { return &v }
