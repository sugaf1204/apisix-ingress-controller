// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package controller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stypes "k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/apache/apisix-ingress-controller/api/v1alpha1"
	"github.com/apache/apisix-ingress-controller/internal/controller/config"
)

func newListenerSetTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, gatewayv1.Install(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))
	return scheme
}

func TestListenerSetReconcile_AllowedAndAccepted(t *testing.T) {
	scheme := newListenerSetTestScheme(t)

	config.ControllerConfig.ControllerName = "apisix.apache.org/gateway-controller"

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "apisix"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(config.ControllerConfig.ControllerName),
		},
	}

	fromAll := gatewayv1.NamespacesFromAll
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "platform",
			Name:      "shared-gw",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "apisix",
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{
					From: &fromAll,
				},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http-80",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Conditions: []metav1.Condition{
				{
					Type:   string(gatewayv1.GatewayConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: string(gatewayv1.GatewayReasonAccepted),
				},
			},
		},
	}

	certPEM, keyPEM := generateTestCertificate(t, "app.example.com")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "app",
			Name:      "app-tls",
		},
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}

	parentRefNs := gatewayv1.Namespace("platform")
	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "app",
			Name:      "app-listeners",
		},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{
				Namespace: &parentRefNs,
				Name:      gatewayv1.ObjectName("shared-gw"),
			},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "https-8443",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: ptr.To(gatewayv1.Hostname("app.example.com")),
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: ptr.To(gatewayv1.TLSModeTerminate),
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{
								Kind: ptr.To(gatewayv1.Kind("Secret")),
								Name: gatewayv1.ObjectName("app-tls"),
							},
						},
					},
				},
			},
		},
	}

	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gc, gw, secret, ls).
		Build()

	prov := &recordingProvider{}
	updater := &recordingUpdater{}

	r := &ListenerSetReconciler{
		Client:   cli,
		Scheme:   scheme,
		Log:      logr.Discard(),
		Provider: prov,
		Updater:  updater,
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: k8stypes.NamespacedName{Namespace: ls.Namespace, Name: ls.Name},
	})
	require.NoError(t, err)
	assert.False(t, result.Requeue)
	assert.Equal(t, 1, prov.updated)

	require.NotEmpty(t, updater.updates)
	lastUpdate := updater.updates[len(updater.updates)-1]
	mutated := lastUpdate.Mutator.Mutate(ls.DeepCopy()).(*gatewayv1.ListenerSet)
	acceptedCond := getListenerSetCondition(mutated.Status.Conditions, string(gatewayv1.ListenerSetConditionAccepted))
	require.NotNil(t, acceptedCond)
	assert.Equal(t, metav1.ConditionTrue, acceptedCond.Status)

	progCond := getListenerSetCondition(mutated.Status.Conditions, string(gatewayv1.ListenerSetConditionProgrammed))
	require.NotNil(t, progCond)
	assert.Equal(t, metav1.ConditionTrue, progCond.Status)
}

func TestListenerSetReconcile_NotAllowedByGateway(t *testing.T) {
	scheme := newListenerSetTestScheme(t)
	config.ControllerConfig.ControllerName = "apisix.apache.org/gateway-controller"

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "apisix"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(config.ControllerConfig.ControllerName),
		},
	}

	fromSame := gatewayv1.NamespacesFromSame
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "platform",
			Name:      "shared-gw",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "apisix",
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{
					From: &fromSame,
				},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Conditions: []metav1.Condition{
				{
					Type:   string(gatewayv1.GatewayConditionAccepted),
					Status: metav1.ConditionTrue,
				},
			},
		},
	}

	parentRefNs := gatewayv1.Namespace("platform")
	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "other-namespace",
			Name:      "rejected-ls",
		},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{
				Namespace: &parentRefNs,
				Name:      gatewayv1.ObjectName("shared-gw"),
			},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "http-8080",
					Port:     8080,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gc, gw, ls).
		Build()

	prov := &recordingProvider{}
	updater := &recordingUpdater{}

	r := &ListenerSetReconciler{
		Client:   cli,
		Scheme:   scheme,
		Log:      logr.Discard(),
		Provider: prov,
		Updater:  updater,
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: k8stypes.NamespacedName{Namespace: ls.Namespace, Name: ls.Name},
	})
	require.NoError(t, err)
	assert.Equal(t, 0, prov.updated)
	require.NotEmpty(t, prov.deleted)

	require.NotEmpty(t, updater.updates)
	lastUpdate := updater.updates[len(updater.updates)-1]
	mutated := lastUpdate.Mutator.Mutate(ls.DeepCopy()).(*gatewayv1.ListenerSet)

	acceptedCond := getListenerSetCondition(mutated.Status.Conditions, string(gatewayv1.ListenerSetConditionAccepted))
	require.NotNil(t, acceptedCond)
	assert.Equal(t, metav1.ConditionFalse, acceptedCond.Status)
	assert.Equal(t, string(gatewayv1.ListenerSetReasonNotAllowed), acceptedCond.Reason)
}

func TestListenerSetReconcile_ConflictWithGatewayListener(t *testing.T) {
	scheme := newListenerSetTestScheme(t)
	config.ControllerConfig.ControllerName = "apisix.apache.org/gateway-controller"

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "apisix"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(config.ControllerConfig.ControllerName),
		},
	}

	fromAll := gatewayv1.NamespacesFromAll
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "gw",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "apisix",
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{From: &fromAll},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http-80",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
		Status: gatewayv1.GatewayStatus{
			Conditions: []metav1.Condition{
				{
					Type:   string(gatewayv1.GatewayConditionAccepted),
					Status: metav1.ConditionTrue,
				},
			},
		},
	}

	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "conflict-ls",
		},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{
				Name: gatewayv1.ObjectName("gw"),
			},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "tcp-80",
					Port:     80,
					Protocol: gatewayv1.TCPProtocolType, // Conflict with HTTP on port 80
				},
			},
		},
	}

	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gc, gw, ls).
		Build()

	prov := &recordingProvider{}
	updater := &recordingUpdater{}

	r := &ListenerSetReconciler{
		Client:   cli,
		Scheme:   scheme,
		Log:      logr.Discard(),
		Provider: prov,
		Updater:  updater,
	}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: k8stypes.NamespacedName{Namespace: ls.Namespace, Name: ls.Name},
	})
	require.NoError(t, err)

	require.NotEmpty(t, updater.updates)
	lastUpdate := updater.updates[len(updater.updates)-1]
	mutated := lastUpdate.Mutator.Mutate(ls.DeepCopy()).(*gatewayv1.ListenerSet)

	require.Len(t, mutated.Status.Listeners, 1)
	entryStatus := mutated.Status.Listeners[0]

	conflictedCond := getListenerEntryCondition(entryStatus.Conditions, string(gatewayv1.ListenerEntryConditionConflicted))
	require.NotNil(t, conflictedCond)
	assert.Equal(t, metav1.ConditionTrue, conflictedCond.Status)
	assert.Equal(t, string(gatewayv1.ListenerEntryReasonProtocolConflict), conflictedCond.Reason)

	entryAcceptedCond := getListenerEntryCondition(entryStatus.Conditions, string(gatewayv1.ListenerEntryConditionAccepted))
	require.NotNil(t, entryAcceptedCond)
	assert.Equal(t, metav1.ConditionFalse, entryAcceptedCond.Status)

	overallAccepted := getListenerSetCondition(mutated.Status.Conditions, string(gatewayv1.ListenerSetConditionAccepted))
	require.NotNil(t, overallAccepted)
	assert.Equal(t, metav1.ConditionFalse, overallAccepted.Status)
	assert.Equal(t, string(gatewayv1.ListenerSetReasonListenersNotValid), overallAccepted.Reason)
}

func TestGatewayReconcile_AttachedListenerSets(t *testing.T) {
	scheme := newListenerSetTestScheme(t)
	config.ControllerConfig.ControllerName = "apisix.apache.org/gateway-controller"

	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "apisix"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(config.ControllerConfig.ControllerName),
		},
	}

	fromAll := gatewayv1.NamespacesFromAll
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "gw",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "apisix",
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{From: &fromAll},
			},
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	ls1 := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "ls1"},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{Name: "gw"},
			Listeners: []gatewayv1.ListenerEntry{
				{Name: "http-8080", Port: 8080, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
		Status: gatewayv1.ListenerSetStatus{
			Conditions: []metav1.Condition{
				{Type: string(gatewayv1.ListenerSetConditionAccepted), Status: metav1.ConditionTrue},
			},
		},
	}

	ls2 := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "ls2"},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{Name: "gw"},
			Listeners: []gatewayv1.ListenerEntry{
				{Name: "http-8081", Port: 8081, Protocol: gatewayv1.HTTPProtocolType},
			},
		},
		Status: gatewayv1.ListenerSetStatus{
			Conditions: []metav1.Condition{
				{Type: string(gatewayv1.ListenerSetConditionAccepted), Status: metav1.ConditionFalse},
			},
		},
	}

	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gc, gw, ls1, ls2).
		Build()

	r := &GatewayReconciler{
		Client:   cli,
		Scheme:   scheme,
		Log:      logr.Discard(),
		Provider: &recordingProvider{},
		Updater:  &recordingUpdater{},
	}

	count, err := r.countAttachedListenerSets(context.Background(), gw)
	require.NoError(t, err)
	require.NotNil(t, count)
	assert.Equal(t, int32(1), *count)
}


func getListenerSetCondition(conditions []metav1.Condition, condType string) *metav1.Condition {
	for _, c := range conditions {
		if c.Type == condType {
			return &c
		}
	}
	return nil
}

func getListenerEntryCondition(conditions []metav1.Condition, condType string) *metav1.Condition {
	for _, c := range conditions {
		if c.Type == condType {
			return &c
		}
	}
	return nil
}

func generateTestCertificate(t *testing.T, hosts ...string) ([]byte, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		template.DNSNames = append(template.DNSNames, h)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM
}

