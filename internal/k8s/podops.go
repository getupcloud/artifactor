package k8s

import (
	"context"
	"fmt"
	"io"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

// ApplyObject creates the given object in the cluster, reusing it when it
// already exists. Returns whether the object already existed. Namespace,
// ServiceAccount, ClusterRole and ClusterRoleBinding objects are never
// overwritten (they are shared infrastructure); a ConfigMap is updated only
// when overwrite is true.
func (c *Client) ApplyObject(ctx context.Context, obj runtime.Object, overwrite bool) (bool, error) {
	switch o := obj.(type) {
	case *corev1.Namespace:
		return c.applyCore(ctx, "namespace", "", o.Name, func() error {
			_, err := c.cs.CoreV1().Namespaces().Create(ctx, o, metav1.CreateOptions{})
			return err
		})
	case *corev1.ServiceAccount:
		return c.applyCore(ctx, "serviceaccount", o.Namespace, o.Name, func() error {
			_, err := c.cs.CoreV1().ServiceAccounts(o.Namespace).Create(ctx, o, metav1.CreateOptions{})
			return err
		})
	case *rbacv1.ClusterRole:
		return c.applyCore(ctx, "clusterrole", "", o.Name, func() error {
			_, err := c.cs.RbacV1().ClusterRoles().Create(ctx, o, metav1.CreateOptions{})
			return err
		})
	case *rbacv1.ClusterRoleBinding:
		return c.applyCore(ctx, "clusterrolebinding", "", o.Name, func() error {
			_, err := c.cs.RbacV1().ClusterRoleBindings().Create(ctx, o, metav1.CreateOptions{})
			return err
		})
	case *corev1.ConfigMap:
		return c.applyConfigMap(ctx, o, overwrite)
	case *unstructured.Unstructured:
		return c.applyUnstructured(ctx, o)
	default:
		return false, fmt.Errorf("unsupported object type %T", obj)
	}
}

// applyUnstructured creates or reuses an unstructured object via the dynamic
// client. Only the cluster-scoped infra kinds used by the in-cluster scan
// (the OpenShift SecurityContextConstraints) are supported; like the other
// infra objects they are never overwritten.
func (c *Client) applyUnstructured(ctx context.Context, obj *unstructured.Unstructured) (bool, error) {
	resource, ok := unstructuredResourceNames[obj.GetKind()]
	if !ok {
		return false, fmt.Errorf("unsupported unstructured kind %q", obj.GetKind())
	}
	gvr := obj.GroupVersionKind().GroupVersion().WithResource(resource)
	_, err := c.dyn.Resource(gvr).Get(ctx, obj.GetName(), metav1.GetOptions{})
	if err == nil {
		return true, nil
	}
	if !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("get %s %q: %w", resource, obj.GetName(), err)
	}
	if _, err := c.dyn.Resource(gvr).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return true, nil
		}
		return false, fmt.Errorf("create %s %q: %w", resource, obj.GetName(), err)
	}
	return false, nil
}

// unstructuredResourceNames maps unstructured kinds used by the in-cluster
// scan to their API resource names (the OpenShift SCC is not part of the
// client-go scheme, so it is handled via the dynamic client).
var unstructuredResourceNames = map[string]string{
	"SecurityContextConstraints": "securitycontextconstraints",
}

// applyCore creates an infra object when it does not exist yet; an existing
// object is reused as-is (shared with `artifactor install`).
func (c *Client) applyCore(ctx context.Context, kind, namespace, name string, create func() error) (bool, error) {
	exists, err := c.objectExists(ctx, kind, namespace, name)
	if err != nil {
		return false, err
	}
	if exists {
		return true, nil
	}
	if err := create(); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return true, nil
		}
		return false, fmt.Errorf("create %s %q: %w", kind, name, err)
	}
	return false, nil
}

// applyConfigMap creates the ConfigMap, or updates it when it already exists
// and overwrite is set.
func (c *Client) applyConfigMap(ctx context.Context, cm *corev1.ConfigMap, overwrite bool) (bool, error) {
	existing, err := c.cs.CoreV1().ConfigMaps(cm.Namespace).Get(ctx, cm.Name, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return false, fmt.Errorf("get configmap %q: %w", cm.Name, err)
		}
		if _, err := c.cs.CoreV1().ConfigMaps(cm.Namespace).Create(ctx, cm, metav1.CreateOptions{}); err != nil {
			if apierrors.IsAlreadyExists(err) {
				return true, nil
			}
			return false, fmt.Errorf("create configmap %q: %w", cm.Name, err)
		}
		return false, nil
	}
	if !overwrite {
		return true, nil
	}
	cm.ResourceVersion = existing.ResourceVersion
	if _, err := c.cs.CoreV1().ConfigMaps(cm.Namespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		return true, fmt.Errorf("update configmap %q: %w", cm.Name, err)
	}
	return true, nil
}

// ObjectExists reports whether the given object already exists in the cluster.
func (c *Client) ObjectExists(ctx context.Context, obj runtime.Object) (bool, error) {
	switch o := obj.(type) {
	case *corev1.Namespace:
		return c.objectExists(ctx, "namespace", "", o.Name)
	case *corev1.ServiceAccount:
		return c.objectExists(ctx, "serviceaccount", o.Namespace, o.Name)
	case *rbacv1.ClusterRole:
		return c.objectExists(ctx, "clusterrole", "", o.Name)
	case *rbacv1.ClusterRoleBinding:
		return c.objectExists(ctx, "clusterrolebinding", "", o.Name)
	case *corev1.ConfigMap:
		return c.objectExists(ctx, "configmap", o.Namespace, o.Name)
	default:
		return false, fmt.Errorf("unsupported object type %T", obj)
	}
}

func (c *Client) objectExists(ctx context.Context, kind, namespace, name string) (bool, error) {
	var err error
	switch kind {
	case "namespace":
		_, err = c.cs.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	case "serviceaccount":
		_, err = c.cs.CoreV1().ServiceAccounts(namespace).Get(ctx, name, metav1.GetOptions{})
	case "clusterrole":
		_, err = c.cs.RbacV1().ClusterRoles().Get(ctx, name, metav1.GetOptions{})
	case "clusterrolebinding":
		_, err = c.cs.RbacV1().ClusterRoleBindings().Get(ctx, name, metav1.GetOptions{})
	case "configmap":
		_, err = c.cs.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
	default:
		return false, fmt.Errorf("unsupported object kind %q", kind)
	}
	if err == nil {
		return true, nil
	}
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return false, fmt.Errorf("get %s %q: %w", kind, name, err)
}

// DeleteObject removes the given object from the cluster.
func (c *Client) DeleteObject(ctx context.Context, obj runtime.Object) error {
	switch o := obj.(type) {
	case *corev1.Namespace:
		return c.cs.CoreV1().Namespaces().Delete(ctx, o.Name, metav1.DeleteOptions{})
	case *corev1.ServiceAccount:
		return c.cs.CoreV1().ServiceAccounts(o.Namespace).Delete(ctx, o.Name, metav1.DeleteOptions{})
	case *rbacv1.ClusterRole:
		return c.cs.RbacV1().ClusterRoles().Delete(ctx, o.Name, metav1.DeleteOptions{})
	case *rbacv1.ClusterRoleBinding:
		return c.cs.RbacV1().ClusterRoleBindings().Delete(ctx, o.Name, metav1.DeleteOptions{})
	case *corev1.ConfigMap:
		return c.cs.CoreV1().ConfigMaps(o.Namespace).Delete(ctx, o.Name, metav1.DeleteOptions{})
	case *corev1.Pod:
		return c.cs.CoreV1().Pods(o.Namespace).Delete(ctx, o.Name, metav1.DeleteOptions{})
	default:
		return fmt.Errorf("unsupported object type %T", obj)
	}
}

// GetPod returns the pod, or found=false when it does not exist.
func (c *Client) GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, bool, error) {
	pod, err := c.cs.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("get pod %q: %w", name, err)
	}
	return pod, true, nil
}

// CreatePod creates the given pod.
func (c *Client) CreatePod(ctx context.Context, pod *corev1.Pod) error {
	_, err := c.cs.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{})
	return err
}

// DeletePod removes the pod and waits for it to be gone.
func (c *Client) DeletePod(ctx context.Context, namespace, name string) error {
	return c.cs.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{})
}

// PodLogs returns the pod container logs (stdout + stderr merged by the
// container runtime). With a non-nil since, only lines logged at or after
// that instant are returned.
func (c *Client) PodLogs(ctx context.Context, namespace, name, container string, since *metav1.Time) (string, error) {
	req := c.cs.CoreV1().Pods(namespace).GetLogs(name, &corev1.PodLogOptions{
		Container: container,
		SinceTime: since,
	})
	data, err := req.DoRaw(ctx)
	if err != nil {
		return "", fmt.Errorf("pod logs: %w", err)
	}
	return string(data), nil
}

// CopyPodFile downloads a file from the pod by exec'ing the artifactor
// binary inside the container (`artifactor cat <path>`) and streaming its
// stdout into w. The command's stderr goes to errW.
func (c *Client) CopyPodFile(ctx context.Context, namespace, pod, container, path string, w io.Writer, errW io.Writer) error {
	req := c.cs.CoreV1().RESTClient().Post().
		Resource("pods").Name(pod).Namespace(namespace).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command: []string{"artifactor", "cat", path},
			Stdin:   false,
			Stdout:  true,
			Stderr:  true,
			TTY:     false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(c.cfg, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("exec %s: %w", path, err)
	}
	return exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: w,
		Stderr: errW,
	})
}
