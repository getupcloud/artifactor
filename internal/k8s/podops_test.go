package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func newTestClient() *Client {
	return &Client{cs: fake.NewSimpleClientset()}
}

func TestApplyObjectNamespace(t *testing.T) {
	ctx := context.Background()
	c := newTestClient()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "artifactor"}}
	existed, err := c.ApplyObject(ctx, ns, false)
	if err != nil {
		t.Fatal(err)
	}
	if existed {
		t.Fatal("new namespace reported as existing")
	}
	existed, err = c.ApplyObject(ctx, ns, false)
	if err != nil {
		t.Fatal(err)
	}
	if !existed {
		t.Fatal("existing namespace reported as new")
	}
	// the existing object must be reused, not overwritten
	ns.Labels = map[string]string{"x": "y"}
	if _, err := c.ApplyObject(ctx, ns, false); err != nil {
		t.Fatal(err)
	}
	got, err := c.cs.CoreV1().Namespaces().Get(ctx, "artifactor", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Labels) != 0 {
		t.Fatalf("infra object was overwritten: %v", got.Labels)
	}
}

func TestApplyObjectInfra(t *testing.T) {
	ctx := context.Background()
	c := newTestClient()

	if _, err := c.ApplyObject(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "artifactor", Namespace: "artifactor"}}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyObject(ctx, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "artifactor"}}, false); err != nil {
		t.Fatal(err)
	}
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "artifactor"},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "artifactor"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "artifactor", Namespace: "artifactor"}},
	}
	existed, err := c.ApplyObject(ctx, crb, false)
	if err != nil {
		t.Fatal(err)
	}
	if existed {
		t.Fatal("new clusterrolebinding reported as existing")
	}
}

func TestApplyObjectConfigMapOverwrite(t *testing.T) {
	ctx := context.Background()
	c := newTestClient()

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "artifactor-db-ca", Namespace: "artifactor"},
		Data:       map[string]string{"ca.crt": "v1"},
	}
	existed, err := c.ApplyObject(ctx, cm, true)
	if err != nil {
		t.Fatal(err)
	}
	if existed {
		t.Fatal("new configmap reported as existing")
	}

	// without overwrite: content unchanged
	cm.Data["ca.crt"] = "v2"
	existed, err = c.ApplyObject(ctx, cm, false)
	if err != nil {
		t.Fatal(err)
	}
	if !existed {
		t.Fatal("existing configmap reported as new")
	}
	got, err := c.cs.CoreV1().ConfigMaps("artifactor").Get(ctx, "artifactor-db-ca", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Data["ca.crt"] != "v1" {
		t.Fatalf("configmap overwritten without overwrite=true: %v", got.Data)
	}

	// with overwrite: content updated
	if _, err := c.ApplyObject(ctx, cm, true); err != nil {
		t.Fatal(err)
	}
	got, err = c.cs.CoreV1().ConfigMaps("artifactor").Get(ctx, "artifactor-db-ca", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Data["ca.crt"] != "v2" {
		t.Fatalf("configmap not overwritten: %v", got.Data)
	}
}

func TestObjectExists(t *testing.T) {
	ctx := context.Background()
	c := newTestClient()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "artifactor"}}
	ok, err := c.ObjectExists(ctx, ns)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("missing namespace reported as existing")
	}
	if _, err := c.ApplyObject(ctx, ns, false); err != nil {
		t.Fatal(err)
	}
	ok, err = c.ObjectExists(ctx, ns)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("existing namespace reported as missing")
	}
}

func TestPodLifecycle(t *testing.T) {
	ctx := context.Background()
	c := newTestClient()

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "artifactor-scan", Namespace: "artifactor"}}
	if _, found, err := c.GetPod(ctx, "artifactor", "artifactor-scan"); err != nil || found {
		t.Fatalf("unexpected pod state: found=%v err=%v", found, err)
	}
	if err := c.CreatePod(ctx, pod); err != nil {
		t.Fatal(err)
	}
	if _, found, err := c.GetPod(ctx, "artifactor", "artifactor-scan"); err != nil || !found {
		t.Fatalf("pod not found after create: found=%v err=%v", found, err)
	}
	if err := c.DeletePod(ctx, "artifactor", "artifactor-scan"); err != nil {
		t.Fatal(err)
	}
	if _, found, err := c.GetPod(ctx, "artifactor", "artifactor-scan"); err != nil || found {
		t.Fatalf("pod still found after delete: found=%v err=%v", found, err)
	}
}

func TestDeleteObject(t *testing.T) {
	ctx := context.Background()
	c := newTestClient()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "artifactor"}}
	if _, err := c.ApplyObject(ctx, ns, false); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteObject(ctx, ns); err != nil {
		t.Fatal(err)
	}
	ok, err := c.ObjectExists(ctx, ns)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("namespace still exists after delete")
	}
}

func TestApplyObjectUnsupported(t *testing.T) {
	c := newTestClient()
	if _, err := c.ApplyObject(context.Background(), &corev1.Pod{}, false); err == nil {
		t.Fatal("expected error for unsupported object type")
	}
}
