// Package k8s discovers container images running in the cluster and resolves
// the imagePullSecrets that apply to each of them.
package k8s

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client wraps the official Kubernetes client.
type Client struct {
	cs  kubernetes.Interface
	cfg *rest.Config
	dyn dynamic.Interface
}

// Instance identifies one workload (namespace + controller) that runs an image.
type Instance struct {
	Namespace  string `json:"namespace"`
	Controller string `json:"controller"`
}

// Discovery holds every unique container image in the cluster, the pull
// secret payloads that apply to each image, and the workloads running it.
type Discovery struct {
	Images []string
	// PullSecrets maps an image to the raw docker config payloads of the
	// pull secrets that apply to it (pod-level secrets first, then service
	// account secrets).
	PullSecrets map[string][][]byte
	// Instances maps an image to the workloads (namespace + controller)
	// running it.
	Instances map[string][]Instance
}

// New builds a client from the in-cluster configuration (kubernetes.default.svc
// service account), falling back to the local kubeconfig for development.
// The returned mode is "in-cluster" or "kubeconfig".
func New() (*Client, string, error) {
	cfg, err := rest.InClusterConfig()
	mode := "in-cluster"
	if err != nil {
		mode = "kubeconfig"
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			if home, herr := os.UserHomeDir(); herr == nil {
				kubeconfig = filepath.Join(home, ".kube", "config")
			}
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, "", fmt.Errorf("no cluster access: in-cluster config unavailable and kubeconfig load failed: %w", err)
		}
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, "", fmt.Errorf("create kubernetes client: %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, "", fmt.Errorf("create dynamic kubernetes client: %w", err)
	}
	return &Client{cs: cs, cfg: cfg, dyn: dyn}, mode, nil
}

// Discover lists pods (restricted to the given namespaces, or all namespaces
// when empty) and collects every unique container image together with the
// docker config payloads of the imagePullSecrets that apply to it and the
// workloads (namespace + controller) running it.
func (c *Client) Discover(ctx context.Context, namespaces []string) (*Discovery, error) {
	pods, err := c.cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	rsOwners, err := c.replicaSetOwners(ctx, namespaces)
	if err != nil {
		return nil, err
	}
	allowed := namespaceSet(namespaces)

	images := map[string]struct{}{}
	pullSecrets := map[string][][]byte{}
	instances := map[string][]Instance{}
	payloadCache := map[string][]byte{} // "ns/name" -> docker config payload
	saCache := map[string]*corev1.ServiceAccount{}

	for i := range pods.Items {
		pod := &pods.Items[i]
		if len(allowed) > 0 {
			if _, ok := allowed[pod.Namespace]; !ok {
				continue
			}
		}
		payloads := c.payloadsForPod(ctx, pod, saCache, payloadCache)
		inst := Instance{Namespace: pod.Namespace, Controller: controllerFor(pod, rsOwners)}

		containers := make([]corev1.Container, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers)+len(pod.Spec.EphemeralContainers))
		containers = append(containers, pod.Spec.Containers...)
		containers = append(containers, pod.Spec.InitContainers...)
		for _, ec := range pod.Spec.EphemeralContainers {
			containers = append(containers, corev1.Container{Image: ec.Image})
		}
		for _, ctr := range containers {
			if ctr.Image == "" {
				continue
			}
			images[ctr.Image] = struct{}{}
			if len(payloads) > 0 {
				pullSecrets[ctr.Image] = mergePayloads(pullSecrets[ctr.Image], payloads)
			}
			instances[ctr.Image] = appendInstance(instances[ctr.Image], inst)
		}
	}

	out := &Discovery{PullSecrets: pullSecrets, Instances: instances}
	for img := range images {
		out.Images = append(out.Images, img)
	}
	sort.Strings(out.Images)
	return out, nil
}

// replicaSetOwners maps "namespace/name" of every ReplicaSet (in the given
// namespaces, or all when empty) to the "kind/name" of the workload that
// owns it (usually a Deployment).
func (c *Client) replicaSetOwners(ctx context.Context, namespaces []string) (map[string]string, error) {
	rss, err := c.cs.AppsV1().ReplicaSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list replicasets: %w", err)
	}
	allowed := namespaceSet(namespaces)
	owners := map[string]string{}
	for i := range rss.Items {
		rs := &rss.Items[i]
		if len(allowed) > 0 {
			if _, ok := allowed[rs.Namespace]; !ok {
				continue
			}
		}
		key := rs.Namespace + "/" + rs.Name
		owners[key] = "replicaset/" + rs.Name
		if ref := controllerRef(rs.OwnerReferences); ref != nil {
			owners[key] = strings.ToLower(ref.Kind) + "/" + ref.Name
		}
	}
	return owners, nil
}

// namespaceSet builds a lookup set from a namespace list.
func namespaceSet(namespaces []string) map[string]struct{} {
	if len(namespaces) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(namespaces))
	for _, ns := range namespaces {
		out[ns] = struct{}{}
	}
	return out
}

// controllerRef returns the owner reference flagged as the controller of the
// object, or nil.
func controllerRef(refs []metav1.OwnerReference) *metav1.OwnerReference {
	for i := range refs {
		if refs[i].Controller != nil && *refs[i].Controller {
			return &refs[i]
		}
	}
	return nil
}

// controllerFor resolves the human-readable controller of a pod, walking the
// ReplicaSet -> Deployment owner chain.
func controllerFor(pod *corev1.Pod, rsOwners map[string]string) string {
	if ref := controllerRef(pod.OwnerReferences); ref != nil {
		if ref.Kind == "ReplicaSet" {
			if owner, ok := rsOwners[pod.Namespace+"/"+ref.Name]; ok {
				return owner
			}
		}
		return strings.ToLower(ref.Kind) + "/" + ref.Name
	}
	return "pod/" + pod.Name
}

func appendInstance(list []Instance, inst Instance) []Instance {
	for _, existing := range list {
		if existing.Namespace == inst.Namespace && existing.Controller == inst.Controller {
			return list
		}
	}
	return append(list, inst)
}

// payloadsForPod resolves the docker config payloads of a pod's pull secrets:
// pod.spec.imagePullSecrets first, then the secrets referenced by the pod's
// service account (imagePullSecrets merged by the SA admission controller).
// Fetch failures are tolerated: a secret we cannot read simply does not
// contribute credentials.
func (c *Client) payloadsForPod(ctx context.Context, pod *corev1.Pod, saCache map[string]*corev1.ServiceAccount, payloadCache map[string][]byte) [][]byte {
	var secretRefs []string
	for _, ps := range pod.Spec.ImagePullSecrets {
		secretRefs = append(secretRefs, ps.Name)
	}

	saName := pod.Spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}
	saKey := pod.Namespace + "/" + saName
	sa, ok := saCache[saKey]
	if !ok {
		sa, _ = c.cs.CoreV1().ServiceAccounts(pod.Namespace).Get(ctx, saName, metav1.GetOptions{})
		saCache[saKey] = sa
	}
	if sa != nil {
		for _, ps := range sa.ImagePullSecrets {
			secretRefs = append(secretRefs, ps.Name)
		}
	}

	var payloads [][]byte
	for _, name := range secretRefs {
		cacheKey := pod.Namespace + "/" + name
		payload, cached := payloadCache[cacheKey]
		if !cached {
			payload = c.secretPayload(ctx, pod.Namespace, name)
			payloadCache[cacheKey] = payload
		}
		if len(payload) > 0 {
			payloads = appendUniquePayload(payloads, payload)
		}
	}
	return payloads
}

func (c *Client) secretPayload(ctx context.Context, namespace, name string) []byte {
	secret, err := c.cs.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil
	}
	for _, key := range []string{corev1.DockerConfigJsonKey, corev1.DockerConfigKey} {
		if payload, ok := secret.Data[key]; ok && len(payload) > 0 {
			return payload
		}
	}
	return nil
}

func appendUniquePayload(list [][]byte, payload []byte) [][]byte {
	for _, existing := range list {
		if bytes.Equal(existing, payload) {
			return list
		}
	}
	return append(list, payload)
}

func mergePayloads(dst, src [][]byte) [][]byte {
	for _, payload := range src {
		dst = appendUniquePayload(dst, payload)
	}
	return dst
}
