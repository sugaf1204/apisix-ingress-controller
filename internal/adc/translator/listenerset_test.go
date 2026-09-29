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

package translator

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/apache/apisix-ingress-controller/internal/controller/label"
	"github.com/apache/apisix-ingress-controller/internal/provider"
	internaltypes "github.com/apache/apisix-ingress-controller/internal/types"
)

func newTLSListenerSet() *gatewayv1.ListenerSet {
	return &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      "test-ls",
		},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{
				Name: "gw",
			},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "https",
					Port:     8443,
					Protocol: gatewayv1.HTTPSProtocolType,
					Hostname: ptr.To(gatewayv1.Hostname("app.example.com")),
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: ptr.To(gatewayv1.TLSModeTerminate),
						CertificateRefs: []gatewayv1.SecretObjectReference{
							{
								Kind: ptr.To(gatewayv1.Kind("Secret")),
								Name: gatewayv1.ObjectName("server-cert"),
							},
						},
					},
				},
			},
		},
	}
}

func TestTranslateListenerSet_TLS(t *testing.T) {
	tr := &Translator{Log: logr.Discard()}
	ls := newTLSListenerSet()

	tctx := provider.NewDefaultTranslateContext(context.Background())
	tctx.Secrets[types.NamespacedName{Namespace: "test-ns", Name: "server-cert"}] = &corev1.Secret{
		Data: map[string][]byte{
			"cert": []byte("server-cert-data"),
			"key":  []byte("server-key-data"),
		},
	}

	result, err := tr.TranslateListenerSet(tctx, ls)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.SSL, 1)

	ssl := result.SSL[0]
	assert.Equal(t, []string{"app.example.com"}, ssl.Snis)
	require.Len(t, ssl.Certificates, 1)
	assert.Equal(t, "server-cert-data", ssl.Certificates[0].Certificate)
	assert.Equal(t, "server-key-data", ssl.Certificates[0].Key)
	assert.Equal(t, internaltypes.KindListenerSet, ssl.Labels[label.LabelKind])
	assert.Equal(t, "test-ns", ssl.Labels[label.LabelNamespace])
	assert.Equal(t, "test-ls", ssl.Labels[label.LabelName])
}

func TestTranslateListenerSet_Passthrough(t *testing.T) {
	tr := &Translator{Log: logr.Discard()}
	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      "test-ls",
		},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{Name: "gw"},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "tls-pass",
					Port:     8443,
					Protocol: gatewayv1.TLSProtocolType,
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: ptr.To(gatewayv1.TLSModePassthrough),
					},
				},
			},
		},
	}

	tctx := provider.NewDefaultTranslateContext(context.Background())
	result, err := tr.TranslateListenerSet(tctx, ls)
	require.NoError(t, err)
	assert.Empty(t, result.SSL)
}

func TestTranslateListenerSet_HTTP(t *testing.T) {
	tr := &Translator{Log: logr.Discard()}
	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test-ns",
			Name:      "test-ls",
		},
		Spec: gatewayv1.ListenerSetSpec{
			ParentRef: gatewayv1.ParentGatewayReference{Name: "gw"},
			Listeners: []gatewayv1.ListenerEntry{
				{
					Name:     "http",
					Port:     8080,
					Protocol: gatewayv1.HTTPProtocolType,
				},
			},
		},
	}

	tctx := provider.NewDefaultTranslateContext(context.Background())
	result, err := tr.TranslateListenerSet(tctx, ls)
	require.NoError(t, err)
	assert.Empty(t, result.SSL)
}
