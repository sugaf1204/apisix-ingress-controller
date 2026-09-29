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
	"fmt"

	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	adctypes "github.com/apache/apisix-ingress-controller/api/adc"
	"github.com/apache/apisix-ingress-controller/internal/controller/label"
	"github.com/apache/apisix-ingress-controller/internal/id"
	"github.com/apache/apisix-ingress-controller/internal/provider"
	sslutils "github.com/apache/apisix-ingress-controller/internal/ssl"
	internaltypes "github.com/apache/apisix-ingress-controller/internal/types"
)

func (t *Translator) TranslateListenerSet(tctx *provider.TranslateContext, obj *gatewayv1.ListenerSet) (*TranslateResult, error) {
	if obj.TypeMeta.Kind == "" {
		obj.TypeMeta = metav1.TypeMeta{
			Kind:       internaltypes.KindListenerSet,
			APIVersion: gatewayv1.GroupVersion.String(),
		}
	}
	result := &TranslateResult{}
	for _, listener := range obj.Spec.Listeners {
		if listener.TLS != nil {
			tctx.GatewayTLSConfig = append(tctx.GatewayTLSConfig, *listener.TLS)
			ssl, err := t.translateListenerSetSecret(tctx, listener, obj)
			if err != nil {
				return nil, fmt.Errorf("failed to translate secret: %w", err)
			}
			result.SSL = append(result.SSL, ssl...)
		}
	}

	return result, nil
}

func (t *Translator) translateListenerSetSecret(tctx *provider.TranslateContext, listener gatewayv1.ListenerEntry, obj *gatewayv1.ListenerSet) ([]*adctypes.SSL, error) {
	if tctx.Secrets == nil {
		return nil, nil
	}
	sslObjs := make([]*adctypes.SSL, 0)

	mode := gatewayv1.TLSModeTerminate
	if listener.TLS.Mode != nil {
		mode = *listener.TLS.Mode
	}
	if mode == gatewayv1.TLSModePassthrough {
		return sslObjs, nil
	}

	if listener.TLS.CertificateRefs == nil {
		return nil, fmt.Errorf("no certificateRefs found in listener %s", listener.Name)
	}

	switch mode {
	case gatewayv1.TLSModeTerminate:
		for refIndex, ref := range listener.TLS.CertificateRefs {
			ns := obj.GetNamespace()
			if ref.Namespace != nil {
				ns = string(*ref.Namespace)
			}
			if len(listener.TLS.CertificateRefs) > 0 &&
				(listener.TLS.CertificateRefs[0].Kind == nil || *listener.TLS.CertificateRefs[0].Kind == internaltypes.KindSecret) {
				sslObj := &adctypes.SSL{
					Snis: []string{},
				}
				name := string(ref.Name)
				secretNN := types.NamespacedName{Namespace: ns, Name: name}
				secret := tctx.Secrets[secretNN]
				if secret == nil {
					continue
				}
				if secret.Data == nil {
					t.Log.Error(errors.New("secret data is nil"), "failed to get secret data", "secret", secretNN)
					return nil, fmt.Errorf("no secret data found for %s/%s", ns, name)
				}
				cert, key, err := sslutils.ExtractKeyPair(secret, true)
				if err != nil {
					t.Log.Error(err, "extract key pair", "secret", secretNN)
					return nil, err
				}
				sslObj.Certificates = append(sslObj.Certificates, adctypes.Certificate{
					Certificate: string(cert),
					Key:         string(key),
				})
				if listener.Hostname != nil && *listener.Hostname != "" {
					sslObj.Snis = append(sslObj.Snis, string(*listener.Hostname))
				} else {
					hosts, err := sslutils.ExtractHostsFromCertificate(cert)
					if err != nil {
						return nil, err
					}
					if len(hosts) == 0 {
						t.Log.Info("no valid hostname found in certificate", "secret", secretNN.String())
						continue
					}
					sslObj.Snis = append(sslObj.Snis, hosts...)
				}
				sslObj.Snis = sslutils.NormalizeHosts(sslObj.Snis)
				sslObj.ID = id.GenID(adctypes.ComposeGatewayListenerSSLName(internaltypes.KindListenerSet, obj.Namespace, obj.Name, string(listener.Name), refIndex))
				t.Log.V(1).Info("generated ssl id", "ssl id", sslObj.ID, "secret", secretNN.String())
				sslObj.Labels = label.GenLabel(obj)
				sslObjs = append(sslObjs, sslObj)
			}
		}
	default:
		return nil, fmt.Errorf("unknown TLS mode %s", mode)
	}

	return sslObjs, nil
}
