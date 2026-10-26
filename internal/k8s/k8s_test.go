package k8s

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ctrl(controller bool, kind, name string) metav1.OwnerReference {
	return metav1.OwnerReference{APIVersion: "apps/v1", Kind: kind, Name: name, Controller: &controller}
}

func TestControllerFor(t *testing.T) {
	rsOwners := map[string]string{"web/nginx-abc123": "deployment/nginx"}

	cases := []struct {
		name string
		pod  *corev1.Pod
		want string
	}{
		{"replicaset resolves to deployment",
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "web", OwnerReferences: []metav1.OwnerReference{ctrl(true, "ReplicaSet", "nginx-abc123")}}},
			"deployment/nginx"},
		{"unknown replicaset falls back to itself",
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "web", OwnerReferences: []metav1.OwnerReference{ctrl(true, "ReplicaSet", "other")}}},
			"replicaset/other"},
		{"statefulset direct",
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "db", OwnerReferences: []metav1.OwnerReference{ctrl(true, "StatefulSet", "pg")}}},
			"statefulset/pg"},
		{"daemonset direct",
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "kube-system", OwnerReferences: []metav1.OwnerReference{ctrl(true, "DaemonSet", "kube-proxy")}}},
			"daemonset/kube-proxy"},
		{"job direct",
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "batch", OwnerReferences: []metav1.OwnerReference{ctrl(true, "Job", "migrate")}}},
			"job/migrate"},
		{"no controller owner -> pod itself",
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "bare", Namespace: "ns"}},
			"pod/bare"},
		{"non-controller owner ignored -> pod itself",
			&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p2", Namespace: "ns", OwnerReferences: []metav1.OwnerReference{ctrl(false, "ReplicaSet", "x")}}},
			"pod/p2"},
	}
	for _, tc := range cases {
		if got := controllerFor(tc.pod, rsOwners); got != tc.want {
			t.Errorf("%s: controllerFor = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestControllerRef(t *testing.T) {
	refs := []metav1.OwnerReference{ctrl(false, "ConfigMap", "cm"), ctrl(true, "ReplicaSet", "rs")}
	got := controllerRef(refs)
	if got == nil || got.Kind != "ReplicaSet" {
		t.Fatalf("controllerRef = %v", got)
	}
	if controllerRef([]metav1.OwnerReference{ctrl(false, "X", "y")}) != nil {
		t.Fatal("expected nil for no controller ref")
	}
}

func TestAppendInstanceDedup(t *testing.T) {
	list := appendInstance(nil, Instance{Namespace: "a", Controller: "deployment/x"})
	list = appendInstance(list, Instance{Namespace: "a", Controller: "deployment/x"})
	list = appendInstance(list, Instance{Namespace: "b", Controller: "deployment/x"})
	if len(list) != 2 {
		t.Fatalf("list = %v, want 2 deduped entries", list)
	}
}
