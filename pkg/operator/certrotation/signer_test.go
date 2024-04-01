package certrotation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/go-cmp/cmp"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubefake "k8s.io/client-go/kubernetes/fake"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/api/annotations"
	"github.com/openshift/library-go/pkg/operator/events"
	"k8s.io/apimachinery/pkg/labels"
)

type dispatcher struct {
	t        *testing.T
	source   rand.Source
	requests chan request
}

type request struct {
	who  string
	what string
	when chan<- struct{}
}

func (d *dispatcher) Sequence(who, what string) {
	signal := make(chan struct{})
	d.requests <- request{
		who:  who,
		what: what,
		when: signal,
	}
	<-signal
}

func (d *dispatcher) Join(who string) {
	signal := make(chan struct{})
	d.requests <- request{
		who:  who,
		what: "JOIN",
		when: signal,
	}
}

func (d *dispatcher) Leave(who string) {
	signal := make(chan struct{})
	d.requests <- request{
		who:  who,
		what: "LEAVE",
		when: signal,
	}
}

func (d *dispatcher) Stop() {
	close(d.requests)
}

func (d *dispatcher) Run() {
	members := make(map[string]struct{})
	var waiting []request
	rng := rand.New(d.source)

	dispatch := func() {
		slices.SortFunc(waiting, func(a, b request) int {
			if a.who == b.who {
				panic(fmt.Sprintf("two concurrent requests from same actor %q", a.who))
			}
			if a.who < b.who {
				return -1
			}
			return 1
		})
		rng.Shuffle(len(waiting), func(i, j int) {
			waiting[i], waiting[j] = waiting[j], waiting[i]
		})
		w := waiting[len(waiting)-1]
		waiting = waiting[:len(waiting)-1]
		d.t.Logf("dispatching %q by %q", w.what, w.who)
		close(w.when)
	}

	for r := range d.requests {
		switch r.what {
		case "JOIN":
			if _, ok := members[r.who]; ok {
				d.t.Fatalf("double join by actor %q", r.who)
			}
			members[r.who] = struct{}{}
			d.t.Logf("%q joined", r.who)
		case "LEAVE":
			if _, ok := members[r.who]; !ok {
				d.t.Fatalf("double leave by actor %q", r.who)
			}
			delete(members, r.who)
			d.t.Logf("%q left", r.who)
		default:
			waiting = append(waiting, r)
		}

		for len(waiting) > 0 && len(waiting) >= len(members) {
			dispatch()
		}
	}

	for range waiting {
		dispatch()
	}
}

type fakeSecretLister struct {
	who        string
	dispatcher *dispatcher
	tracker    clienttesting.ObjectTracker
}

func (l *fakeSecretLister) List(selector labels.Selector) (ret []*v1.Secret, err error) {
	return l.Secrets("").List(selector)
}

func (l *fakeSecretLister) Secrets(namespace string) corev1listers.SecretNamespaceLister {
	return &fakeSecretNamespaceLister{
		who:        l.who,
		dispatcher: l.dispatcher,
		tracker:    l.tracker,
		ns:         namespace,
	}
}

type fakeSecretNamespaceLister struct {
	who        string
	dispatcher *dispatcher
	tracker    clienttesting.ObjectTracker
	ns         string
}

func (l *fakeSecretNamespaceLister) List(selector labels.Selector) (ret []*v1.Secret, err error) {
	obj, err := l.tracker.List(
		schema.GroupVersionResource{Version: "v1", Resource: "secrets"},
		schema.GroupVersionKind{Version: "v1", Kind: "Secret"},
		l.ns,
	)
	var secrets []*v1.Secret
	if l, ok := obj.(*v1.SecretList); ok {
		for i := range l.Items {
			secrets = append(secrets, &l.Items[i])
		}
	}
	return secrets, err
}

func (l *fakeSecretNamespaceLister) Get(name string) (*v1.Secret, error) {
	l.dispatcher.Sequence(l.who, "before-lister-get")
	obj, err := l.tracker.Get(schema.GroupVersionResource{Version: "v1", Resource: "secrets"}, l.ns, name)
	l.dispatcher.Sequence(l.who, "after-lister-get")
	if secret, ok := obj.(*v1.Secret); ok {
		return secret, err
	}
	return nil, err
}

func FuzzEnsureSigningCertKeyPair(f *testing.F) {
	const (
		WorkerCount                 = 3
		SecretNamespace, SecretName = "ns", "test-signer"
	)
	// represents a secret that was created before 4.7 and
	// hasn't been updated until now (upgrade to 4.15)
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:       SecretNamespace,
			Name:            SecretName,
			ResourceVersion: "10",
		},
		Type: "SecretTypeTLS",
		Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
	}
	if err := setSigningCertKeyPairSecret(existing, 24*time.Hour); err != nil {
		f.Fatal(err)
	}
	// give it a second so we have a unique signer name,
	// and also unique not-after, and not-before values
	<-time.After(2 * time.Second)

	f.Fuzz(func(t *testing.T, seed int64) {
		d := &dispatcher{
			t:        t,
			source:   rand.NewSource(seed),
			requests: make(chan request, WorkerCount),
		}
		go d.Run()
		defer d.Stop()

		existing = existing.DeepCopy()

		// get the original crt and key bytes to compare later
		tlsCertWant, ok := existing.Data["tls.crt"]
		if !ok || len(tlsCertWant) == 0 {
			t.Fatalf("missing data in 'tls.crt' key of Data: %#v", existing.Data)
		}
		tlsKeyWant, ok := existing.Data["tls.key"]
		if !ok || len(tlsKeyWant) == 0 {
			t.Fatalf("missing data in 'tls.key' key of Data: %#v", existing.Data)
		}

		secretWant := existing.DeepCopy()

		clientset := kubefake.NewSimpleClientset(existing)

		options := events.RecommendedClusterSingletonCorrelatorOptions()
		client := clientset.CoreV1().Secrets(SecretNamespace)

		var wg sync.WaitGroup
		for i := 1; i <= WorkerCount; i++ {
			controllerName := fmt.Sprintf("controller-%d", i)
			wg.Add(1)
			d.Join(controllerName)

			go func(controllerName string) {
				defer func() {
					d.Leave(controllerName)
					wg.Done()
				}()

				recorder := events.NewKubeRecorderWithOptions(clientset.CoreV1().Events(SecretNamespace), options, "operator", &corev1.ObjectReference{Name: controllerName, Namespace: SecretNamespace})
				wrapped := &wrapped{SecretInterface: client, name: controllerName, t: t, d: d}
				getter := &getter{w: wrapped}
				ctrl := &RotatedSigningCASecret{
					Namespace: SecretNamespace,
					Name:      SecretName,
					Validity:  24 * time.Hour,
					Refresh:   12 * time.Hour,
					Client:    getter,
					Lister: &fakeSecretLister{
						who:        controllerName,
						dispatcher: d,
						tracker:    clientset.Tracker(),
					},
					AdditionalAnnotations: AdditionalAnnotations{JiraComponent: "test"},
					Owner:                 &metav1.OwnerReference{Name: "operator"},
					EventRecorder:         recorder,
				}

				d.Sequence(controllerName, "begin")
				_, err := ctrl.EnsureSigningCertKeyPair(context.TODO())
				if err != nil {
					t.Logf("error from %s: %v", controllerName, err)
				}
			}(controllerName)
		}

		wg.Wait()
		t.Log("controllers done")
		// controllers are done, we don't expect the signer to change
		secretGot, err := client.Get(context.TODO(), SecretName, metav1.GetOptions{})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if tlsCertGot, ok := secretGot.Data["tls.crt"]; !ok || !bytes.Equal(tlsCertWant, tlsCertGot) {
			t.Errorf("the signer cert has mutated unexpectedly")
		}
		if tlsKeyGot, ok := secretGot.Data["tls.key"]; !ok || !bytes.Equal(tlsKeyWant, tlsKeyGot) {
			t.Errorf("the signer cert has mutated unexpectedly")
		}
		if got, exists := secretGot.Annotations["openshift.io/owning-component"]; !exists || got != "test" {
			t.Errorf("owner annotation is missing: %#v", secretGot.Annotations)
		}
		t.Logf("diff: %s", cmp.Diff(secretWant, secretGot))
	})
}

type getter struct {
	w *wrapped
}

func (g *getter) Secrets(string) corev1client.SecretInterface {
	return g.w
}

type wrapped struct {
	corev1client.SecretInterface
	d    *dispatcher
	name string
	t    *testing.T
}

func (w wrapped) Create(ctx context.Context, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error) {
	w.d.Sequence(w.name, "before-create")
	secret, err := w.SecretInterface.Create(ctx, secret, opts)
	w.d.Sequence(w.name, "after-create")
	return secret, err
}
func (w wrapped) Update(ctx context.Context, secret *corev1.Secret, opts metav1.UpdateOptions) (*corev1.Secret, error) {
	w.d.Sequence(w.name, "before-update")
	secret, err := w.SecretInterface.Update(ctx, secret, opts)
	w.d.Sequence(w.name, "after-update")
	j, _ := json.MarshalIndent(secret, "", "  ")
	w.t.Logf("[%s] op=Update, secret:\n%s\nerr: %v", w.name, string(j), err)
	return secret, err
}
func (w wrapped) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	w.d.Sequence(w.name, "before-delete")
	err := w.SecretInterface.Delete(ctx, name, opts)
	w.d.Sequence(w.name, "after-delete")
	return err
}
func (w wrapped) Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.Secret, error) {
	w.d.Sequence(w.name, "before-get")
	obj, err := w.SecretInterface.Get(ctx, name, opts)
	w.d.Sequence(w.name, "after-get")
	j, _ := json.MarshalIndent(obj, "", "  ")
	w.t.Logf("[%s] op=Get, secret:\n%s\nerr: %v", w.name, string(j), err)
	return obj, err
}

func TestEnsureSigningCertKeyPair(t *testing.T) {
	tests := []struct {
		name string

		initialSecret *corev1.Secret

		verifyActions func(t *testing.T, client *kubefake.Clientset)
		expectedError string
	}{
		{
			name: "initial create",
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				t.Helper()
				actions := client.Actions()
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "secrets") {
					t.Error(actions[0])
				}
				if !actions[1].Matches("create", "secrets") {
					t.Error(actions[1])
				}

				actual := actions[1].(clienttesting.CreateAction).GetObject().(*corev1.Secret)
				if certType, _ := CertificateTypeFromObject(actual); certType != CertificateTypeSigner {
					t.Errorf("expected certificate type 'signer', got: %v", certType)
				}
				if len(actual.Data["tls.crt"]) == 0 || len(actual.Data["tls.key"]) == 0 {
					t.Error(actual.Data)
				}
				if len(actual.Annotations) == 0 {
					t.Errorf("expected certificates to be annotated")
				}
				ownershipValue, found := actual.Annotations[annotations.OpenShiftComponent]
				if !found {
					t.Errorf("expected secret to have ownership annotations, got: %v", actual.Annotations)
				}
				if ownershipValue != "test" {
					t.Errorf("expected ownership annotation to be 'test', got: %v", ownershipValue)
				}
				if len(actual.OwnerReferences) != 1 {
					t.Errorf("expected to have exactly one owner reference")
				}
				if actual.OwnerReferences[0].Name != "operator" {
					t.Errorf("expected owner reference to be 'operator', got %v", actual.OwnerReferences[0].Name)
				}
			},
		},
		{
			name: "update no annotations",
			initialSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "signer", ResourceVersion: "10"},
				Type:       corev1.SecretTypeTLS,
				Data:       map[string][]byte{"tls.crt": {}, "tls.key": {}},
			},
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				t.Helper()
				actions := client.Actions()
				if len(actions) != 2 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "secrets") {
					t.Error(actions[0])
				}
				if !actions[1].Matches("update", "secrets") {
					t.Error(actions[1])
				}
				actual := actions[1].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
				if certType, _ := CertificateTypeFromObject(actual); certType != CertificateTypeSigner {
					t.Errorf("expected certificate type 'signer', got: %v", certType)
				}
				if len(actual.Data["tls.crt"]) == 0 || len(actual.Data["tls.key"]) == 0 {
					t.Error(actual.Data)
				}
				ownershipValue, found := actual.Annotations[annotations.OpenShiftComponent]
				if !found {
					t.Errorf("expected secret to have ownership annotations, got: %v", actual.Annotations)
				}
				if ownershipValue != "test" {
					t.Errorf("expected ownership annotation to be 'test', got: %v", ownershipValue)
				}
				if len(actual.OwnerReferences) != 1 {
					t.Errorf("expected to have exactly one owner reference")
				}
				if actual.OwnerReferences[0].Name != "operator" {
					t.Errorf("expected owner reference to be 'operator', got %v", actual.OwnerReferences[0].Name)
				}
			},
		},
		{
			name: "update no work",
			initialSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "signer",
					ResourceVersion: "10",
					Annotations: map[string]string{
						"auth.openshift.io/certificate-not-after":  "2108-09-08T22:47:31-07:00",
						"auth.openshift.io/certificate-not-before": "2108-09-08T20:47:31-07:00",
						annotations.OpenShiftComponent:             "test",
					}},
				Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
			},
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				t.Helper()
				actions := client.Actions()
				if len(actions) != 0 {
					t.Fatal(spew.Sdump(actions))
				}
			},
			expectedError: "certFile missing", // this means we tried to read the cert from the existing secret.  If we created one, we fail in the client check
		},
		{
			name: "update SecretTLSType secrets",
			initialSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "signer",
					ResourceVersion: "10",
					Annotations: map[string]string{
						"auth.openshift.io/certificate-not-after":  "2108-09-08T22:47:31-07:00",
						"auth.openshift.io/certificate-not-before": "2108-09-08T20:47:31-07:00",
					}},
				Type: "SecretTypeTLS",
				Data: map[string][]byte{"tls.crt": {}, "tls.key": {}},
			},
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				t.Helper()
				actions := client.Actions()
				if len(actions) != 3 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "secrets") {
					t.Error(actions[0])
				}
				if !actions[1].Matches("delete", "secrets") {
					t.Error(actions[1])
				}
				if !actions[2].Matches("create", "secrets") {
					t.Error(actions[2])
				}
				actual := actions[2].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
				if actual.Type != corev1.SecretTypeTLS {
					t.Errorf("expected secret type to be kubernetes.io/tls, got: %v", actual.Type)
				}
				cert, found := actual.Data["tls.crt"]
				if !found {
					t.Errorf("expected to have tls.crt key")
				}
				if len(cert) != 0 {
					t.Errorf("expected tls.crt to be empty, got %v", cert)
				}
				key, found := actual.Data["tls.key"]
				if !found {
					t.Errorf("expected to have tls.key key")
				}
				if len(key) != 0 {
					t.Errorf("expected tls.key to be empty, got %v", key)
				}
				if len(actual.OwnerReferences) != 1 {
					t.Errorf("expected to have exactly one owner reference")
				}
				if actual.OwnerReferences[0].Name != "operator" {
					t.Errorf("expected owner reference to be 'operator', got %v", actual.OwnerReferences[0].Name)
				}
			},
			expectedError: "certFile missing", // this means we tried to read the cert from the existing secret.  If we created one, we fail in the client check
		},
		{
			name: "recreate invalid type secrets",
			initialSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "signer",
					ResourceVersion: "10",
					Annotations: map[string]string{
						"auth.openshift.io/certificate-not-after":  "2108-09-08T22:47:31-07:00",
						"auth.openshift.io/certificate-not-before": "2108-09-08T20:47:31-07:00",
					}},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{"foo": {}, "bar": {}},
			},
			verifyActions: func(t *testing.T, client *kubefake.Clientset) {
				t.Helper()
				actions := client.Actions()
				if len(actions) != 3 {
					t.Fatal(spew.Sdump(actions))
				}

				if !actions[0].Matches("get", "secrets") {
					t.Error(actions[0])
				}
				if !actions[1].Matches("delete", "secrets") {
					t.Error(actions[1])
				}
				if !actions[2].Matches("create", "secrets") {
					t.Error(actions[2])
				}
				actual := actions[2].(clienttesting.UpdateAction).GetObject().(*corev1.Secret)
				if actual.Type != corev1.SecretTypeTLS {
					t.Errorf("expected secret type to be kubernetes.io/tls, got: %v", actual.Type)
				}
				if len(actual.OwnerReferences) != 1 {
					t.Errorf("expected to have exactly one owner reference")
				}
				if actual.OwnerReferences[0].Name != "operator" {
					t.Errorf("expected owner reference to be 'operator', got %v", actual.OwnerReferences[0].Name)
				}
			},
			expectedError: "certFile missing", // this means we tried to read the cert from the existing secret.  If we created one, we fail in the client check
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

			client := kubefake.NewSimpleClientset()
			if test.initialSecret != nil {
				indexer.Add(test.initialSecret)
				client = kubefake.NewSimpleClientset(test.initialSecret)
			}

			c := &RotatedSigningCASecret{
				Namespace:     "ns",
				Name:          "signer",
				Validity:      24 * time.Hour,
				Refresh:       12 * time.Hour,
				Client:        client.CoreV1(),
				Lister:        corev1listers.NewSecretLister(indexer),
				EventRecorder: events.NewInMemoryRecorder("test"),
				AdditionalAnnotations: AdditionalAnnotations{
					JiraComponent: "test",
				},
				Owner: &metav1.OwnerReference{
					Name: "operator",
				},
			}

			_, err := c.EnsureSigningCertKeyPair(context.TODO())
			switch {
			case err != nil && len(test.expectedError) == 0:
				t.Error(err)
			case err != nil && !strings.Contains(err.Error(), test.expectedError):
				t.Error(err)
			case err == nil && len(test.expectedError) != 0:
				t.Errorf("missing %q", test.expectedError)
			}

			test.verifyActions(t, client)
		})
	}
}
