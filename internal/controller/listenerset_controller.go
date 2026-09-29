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
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/apache/apisix-ingress-controller/internal/controller/status"
	"github.com/apache/apisix-ingress-controller/internal/provider"
	"github.com/apache/apisix-ingress-controller/internal/utils"
	pkgutils "github.com/apache/apisix-ingress-controller/pkg/utils"
)

// ListenerSetReconciler reconciles a ListenerSet object.
type ListenerSetReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Log      logr.Logger
	Provider provider.Provider
	Updater  status.Updater
}

// SetupWithManager sets up the controller with the Manager.
func (r *ListenerSetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	bdr := ctrl.NewControllerManagedBy(mgr).
		For(
			&gatewayv1.ListenerSet{},
			builder.WithPredicates(
				predicate.GenerationChangedPredicate{},
			),
		).
		Watches(
			&gatewayv1.Gateway{},
			handler.EnqueueRequestsFromMapFunc(r.listListenerSetsForGateway),
		).
		Watches(
			&gatewayv1.GatewayClass{},
			handler.EnqueueRequestsFromMapFunc(r.listListenerSetsForGatewayClass),
		).
		Watches(
			&gatewayv1.HTTPRoute{},
			handler.EnqueueRequestsFromMapFunc(r.listListenerSetsForHTTPRoute),
		).
		Watches(
			&gatewayv1.GRPCRoute{},
			handler.EnqueueRequestsFromMapFunc(r.listListenerSetsForGRPCRoute),
		).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.listListenerSetsForSecret),
		)

	if GetEnableReferenceGrant() {
		bdr.Watches(
			&gatewayv1.ReferenceGrant{},
			handler.EnqueueRequestsFromMapFunc(r.listListenerSetsForReferenceGrant),
			builder.WithPredicates(referenceGrantPredicates(KindListenerSet)),
		)
	}

	hasTCPRoute, err := pkgutils.HasAPIResource(mgr, &gatewayv1.TCPRoute{})
	if err != nil {
		return err
	}
	if hasTCPRoute {
		bdr.Watches(
			&gatewayv1.TCPRoute{},
			handler.EnqueueRequestsFromMapFunc(r.listListenerSetsForTCPRoute),
		)
	}

	hasTLSRoute, err := pkgutils.HasAPIResource(mgr, &gatewayv1.TLSRoute{})
	if err != nil {
		return err
	}
	if hasTLSRoute {
		bdr.Watches(
			&gatewayv1.TLSRoute{},
			handler.EnqueueRequestsFromMapFunc(r.listListenerSetsForTLSRoute),
		)
	}

	hasUDPRoute, err := pkgutils.HasAPIResource(mgr, &gatewayv1.UDPRoute{})
	if err != nil {
		return err
	}
	if hasUDPRoute {
		bdr.Watches(
			&gatewayv1.UDPRoute{},
			handler.EnqueueRequestsFromMapFunc(r.listListenerSetsForUDPRoute),
		)
	}

	return bdr.Complete(r)
}

func (r *ListenerSetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ls := new(gatewayv1.ListenerSet)
	if err := r.Get(ctx, req.NamespacedName, ls); err != nil {
		if client.IgnoreNotFound(err) == nil {
			ls.Namespace = req.Namespace
			ls.Name = req.Name
			ls.TypeMeta = metav1.TypeMeta{
				Kind:       KindListenerSet,
				APIVersion: gatewayv1.GroupVersion.String(),
			}
			if err := r.Provider.Delete(ctx, ls); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	parentRef := ls.Spec.ParentRef
	if parentRef.Group != nil && *parentRef.Group != gatewayv1.GroupName {
		return r.updateFailedStatus(ctx, ls, gatewayv1.ListenerSetReasonInvalid, "ParentRef Group must be gateway.networking.k8s.io")
	}
	if parentRef.Kind != nil && *parentRef.Kind != KindGateway {
		return r.updateFailedStatus(ctx, ls, gatewayv1.ListenerSetReasonInvalid, "ParentRef Kind must be Gateway")
	}

	parentNs := ls.Namespace
	if parentRef.Namespace != nil {
		parentNs = string(*parentRef.Namespace)
	}

	gw := &gatewayv1.Gateway{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: parentNs, Name: string(parentRef.Name)}, gw); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return r.updateFailedStatus(ctx, ls, gatewayv1.ListenerSetReasonParentNotAccepted, "Parent Gateway not found")
		}
		return ctrl.Result{}, err
	}

	if !r.checkGatewayClass(gw) {
		// Not managed by this controller; ignore
		return ctrl.Result{}, nil
	}

	allowed, err := isListenerSetAllowedByGateway(ctx, r.Client, gw, ls.Namespace)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !allowed {
		return r.updateFailedStatus(ctx, ls, gatewayv1.ListenerSetReasonNotAllowed, "ListenerSet is not allowed by parent Gateway AllowedListeners")
	}

	// Verify parent Gateway is accepted
	gwAccepted := false
	for _, cond := range gw.Status.Conditions {
		if cond.Type == string(gatewayv1.GatewayConditionAccepted) && cond.Status == metav1.ConditionTrue {
			gwAccepted = true
			break
		}
	}
	if !gwAccepted {
		return r.updateFailedStatus(ctx, ls, gatewayv1.ListenerSetReasonParentNotAccepted, "Parent Gateway is not Accepted")
	}

	// Conflict detection with prior listeners (parent Gateway + higher priority sibling ListenerSets)
	priorListeners, err := r.collectPriorListeners(ctx, gw, ls)
	if err != nil {
		return ctrl.Result{}, err
	}

	now := metav1.Now()
	listenerStatuses := make([]gatewayv1.ListenerEntryStatus, 0, len(ls.Spec.Listeners))
	anyListenerAccepted := false
	anyListenerInvalid := false

	tctx := provider.NewDefaultTranslateContext(ctx)

	for _, entry := range ls.Spec.Listeners {
		lStatus := gatewayv1.ListenerEntryStatus{
			Name: entry.Name,
			Conditions: []metav1.Condition{
				{
					Type:               string(gatewayv1.ListenerEntryConditionAccepted),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.ListenerEntryReasonAccepted),
					Message:            "Listener is accepted",
					ObservedGeneration: ls.GetGeneration(),
					LastTransitionTime: now,
				},
				{
					Type:               string(gatewayv1.ListenerEntryConditionProgrammed),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.ListenerEntryReasonProgrammed),
					Message:            "Listener is programmed",
					ObservedGeneration: ls.GetGeneration(),
					LastTransitionTime: now,
				},
				{
					Type:               string(gatewayv1.ListenerEntryConditionConflicted),
					Status:             metav1.ConditionFalse,
					Reason:             string(gatewayv1.ListenerReasonNoConflicts),
					ObservedGeneration: ls.GetGeneration(),
					LastTransitionTime: now,
				},
				{
					Type:               string(gatewayv1.ListenerEntryConditionResolvedRefs),
					Status:             metav1.ConditionTrue,
					Reason:             string(gatewayv1.ListenerEntryReasonResolvedRefs),
					ObservedGeneration: ls.GetGeneration(),
					LastTransitionTime: now,
				},
			},
			SupportedKinds: routeKindsForProtocol(entry.Protocol),
		}

		// Protocol support check
		if !isSupportedProtocol(entry.Protocol) {
			setListenerEntryCondition(&lStatus, string(gatewayv1.ListenerEntryConditionAccepted), metav1.ConditionFalse, string(gatewayv1.ListenerEntryReasonUnsupportedProtocol), fmt.Sprintf("Protocol %s is not supported", entry.Protocol), ls.GetGeneration())
			setListenerEntryCondition(&lStatus, string(gatewayv1.ListenerEntryConditionProgrammed), metav1.ConditionFalse, string(gatewayv1.ListenerEntryReasonInvalid), "Protocol unsupported", ls.GetGeneration())
			anyListenerInvalid = true
			listenerStatuses = append(listenerStatuses, lStatus)
			continue
		}

		// Conflict check
		conflicted, conflictReason := checkListenerConflict(entry, priorListeners)
		if conflicted {
			setListenerEntryCondition(&lStatus, string(gatewayv1.ListenerEntryConditionConflicted), metav1.ConditionTrue, string(conflictReason), "Listener conflicts with a prior listener", ls.GetGeneration())
			setListenerEntryCondition(&lStatus, string(gatewayv1.ListenerEntryConditionAccepted), metav1.ConditionFalse, string(gatewayv1.ListenerEntryReasonPortUnavailable), "Port/Hostname conflict with a prior listener", ls.GetGeneration())
			setListenerEntryCondition(&lStatus, string(gatewayv1.ListenerEntryConditionProgrammed), metav1.ConditionFalse, string(gatewayv1.ListenerEntryReasonPortUnavailable), "Port unavailable due to conflict", ls.GetGeneration())
			anyListenerInvalid = true
			listenerStatuses = append(listenerStatuses, lStatus)
			continue
		}

		// TLS validation
		if entry.Protocol == gatewayv1.HTTPSProtocolType || entry.Protocol == gatewayv1.TLSProtocolType {
			if entry.TLS == nil {
				setListenerEntryCondition(&lStatus, string(gatewayv1.ListenerEntryConditionAccepted), metav1.ConditionFalse, string(gatewayv1.ListenerEntryReasonInvalid), "TLS config is required for HTTPS/TLS protocol", ls.GetGeneration())
				setListenerEntryCondition(&lStatus, string(gatewayv1.ListenerEntryConditionProgrammed), metav1.ConditionFalse, string(gatewayv1.ListenerEntryReasonInvalid), "TLS config is required", ls.GetGeneration())
				anyListenerInvalid = true
				listenerStatuses = append(listenerStatuses, lStatus)
				continue
			}

			// Validate certificateRefs
			mode := gatewayv1.TLSModeTerminate
			if entry.TLS.Mode != nil {
				mode = *entry.TLS.Mode
			}
			if mode == gatewayv1.TLSModeTerminate {
				if len(entry.TLS.CertificateRefs) == 0 {
					setListenerEntryCondition(&lStatus, string(gatewayv1.ListenerEntryConditionResolvedRefs), metav1.ConditionFalse, string(gatewayv1.ListenerEntryReasonInvalidCertificateRef), "No certificateRefs provided", ls.GetGeneration())
					setListenerEntryCondition(&lStatus, string(gatewayv1.ListenerEntryConditionProgrammed), metav1.ConditionFalse, string(gatewayv1.ListenerEntryReasonInvalid), "No certificateRefs", ls.GetGeneration())
					anyListenerInvalid = true
					listenerStatuses = append(listenerStatuses, lStatus)
					continue
				}

				certValid := true
				for _, ref := range entry.TLS.CertificateRefs {
					if ref.Group != nil && *ref.Group != corev1.GroupName {
						setListenerEntryCondition(&lStatus, string(gatewayv1.ListenerEntryConditionResolvedRefs), metav1.ConditionFalse, string(gatewayv1.ListenerEntryReasonInvalidCertificateRef), fmt.Sprintf("Unsupported group %q", *ref.Group), ls.GetGeneration())
						certValid = false
						break
					}
					if ref.Kind != nil && *ref.Kind != KindSecret {
						setListenerEntryCondition(&lStatus, string(gatewayv1.ListenerEntryConditionResolvedRefs), metav1.ConditionFalse, string(gatewayv1.ListenerEntryReasonInvalidCertificateRef), fmt.Sprintf("Unsupported kind %q", *ref.Kind), ls.GetGeneration())
						certValid = false
						break
					}

					refNs := ls.Namespace
					if ref.Namespace != nil {
						refNs = string(*ref.Namespace)
					}

					if !checkReferenceGrant(ctx, r.Client,
						gatewayv1.ReferenceGrantFrom{
							Group:     gatewayv1.GroupName,
							Kind:      KindListenerSet,
							Namespace: gatewayv1.Namespace(ls.Namespace),
						},
						gatewayv1.ObjectReference{
							Group:     corev1.GroupName,
							Kind:      KindSecret,
							Name:      ref.Name,
							Namespace: ref.Namespace,
						},
					) {
						setListenerEntryCondition(&lStatus, string(gatewayv1.ListenerEntryConditionResolvedRefs), metav1.ConditionFalse, string(gatewayv1.ListenerEntryReasonRefNotPermitted), "CertificateRef cross-namespace not permitted by ReferenceGrant", ls.GetGeneration())
						certValid = false
						break
					}

					secretNN := types.NamespacedName{Namespace: refNs, Name: string(ref.Name)}
					var sec corev1.Secret
					if err := r.Get(ctx, secretNN, &sec); err != nil {
						setListenerEntryCondition(&lStatus, string(gatewayv1.ListenerEntryConditionResolvedRefs), metav1.ConditionFalse, string(gatewayv1.ListenerEntryReasonInvalidCertificateRef), err.Error(), ls.GetGeneration())
						certValid = false
						break
					}
					if cause, ok := isTLSSecretValid(&sec); !ok {
						setListenerEntryCondition(&lStatus, string(gatewayv1.ListenerEntryConditionResolvedRefs), metav1.ConditionFalse, string(gatewayv1.ListenerEntryReasonInvalidCertificateRef), fmt.Sprintf("Malformed Secret: %s", cause), ls.GetGeneration())
						certValid = false
						break
					}
					tctx.Secrets[secretNN] = &sec
				}

				if !certValid {
					setListenerEntryCondition(&lStatus, string(gatewayv1.ListenerEntryConditionProgrammed), metav1.ConditionFalse, string(gatewayv1.ListenerEntryReasonInvalid), "Invalid certificateRefs", ls.GetGeneration())
					anyListenerInvalid = true
					listenerStatuses = append(listenerStatuses, lStatus)
					continue
				}
			}
		}

		// Calculate AttachedRoutes
		attachedRoutes, err := r.getAttachedRoutes(ctx, ls, entry)
		if err != nil {
			r.Log.Error(err, "failed to get attached routes for listener", "listener", entry.Name)
		}
		lStatus.AttachedRoutes = attachedRoutes

		anyListenerAccepted = true
		listenerStatuses = append(listenerStatuses, lStatus)
	}

	// Overall conditions
	overallAccepted := metav1.Condition{
		Type:               string(gatewayv1.ListenerSetConditionAccepted),
		Status:             metav1.ConditionTrue,
		Reason:             string(gatewayv1.ListenerSetReasonAccepted),
		Message:            "ListenerSet is accepted",
		ObservedGeneration: ls.GetGeneration(),
		LastTransitionTime: now,
	}
	overallProgrammed := metav1.Condition{
		Type:               string(gatewayv1.ListenerSetConditionProgrammed),
		Status:             metav1.ConditionTrue,
		Reason:             string(gatewayv1.ListenerSetReasonProgrammed),
		Message:            "ListenerSet is programmed",
		ObservedGeneration: ls.GetGeneration(),
		LastTransitionTime: now,
	}

	if !anyListenerAccepted {
		overallAccepted.Status = metav1.ConditionFalse
		overallAccepted.Reason = string(gatewayv1.ListenerSetReasonListenersNotValid)
		overallAccepted.Message = "All listeners are invalid or conflicted"
		overallProgrammed.Status = metav1.ConditionFalse
		overallProgrammed.Reason = string(gatewayv1.ListenerSetReasonListenersNotValid)
		overallProgrammed.Message = "No valid listeners to program"
	} else if anyListenerInvalid {
		overallAccepted.Status = metav1.ConditionTrue
		overallAccepted.Reason = string(gatewayv1.ListenerSetReasonListenersNotValid)
		overallAccepted.Message = "One or more listeners have invalid or conflicted configuration"
	}

	// Sync to data plane
	ls.TypeMeta = metav1.TypeMeta{
		Kind:       KindListenerSet,
		APIVersion: gatewayv1.GroupVersion.String(),
	}

	if anyListenerAccepted {
		rk := utils.NamespacedNameKind(ls)
		if err := ProcessGatewayProxy(r.Client, r.Log, tctx, gw, rk); err != nil {
			r.Log.Error(err, "failed to process gateway proxy for listenerset", "listenerset", ls.Name)
		}
		if err := r.Provider.Update(ctx, tctx, ls); err != nil {
			r.Log.Error(err, "failed to update listenerset in provider", "listenerset", ls.Name)
			overallProgrammed.Status = metav1.ConditionFalse
			overallProgrammed.Reason = string(gatewayv1.ListenerSetReasonInvalid)
			overallProgrammed.Message = err.Error()
		}
	} else {
		if err := r.Provider.Delete(ctx, ls); err != nil {
			r.Log.Error(err, "failed to delete listenerset in provider", "listenerset", ls.Name)
		}
	}

	setListenerSetCondition(ls, overallAccepted)
	setListenerSetCondition(ls, overallProgrammed)
	ls.Status.Listeners = listenerStatuses

	r.Updater.Update(status.Update{
		NamespacedName: utils.NamespacedName(ls),
		Resource:       &gatewayv1.ListenerSet{},
		Mutator: status.MutatorFunc(func(obj client.Object) client.Object {
			target, ok := obj.(*gatewayv1.ListenerSet)
			if !ok {
				panic(fmt.Errorf("unsupported object type %T", obj))
			}
			targetCopy := target.DeepCopy()
			targetCopy.Status = ls.Status
			return targetCopy
		}),
	})

	return ctrl.Result{}, nil
}

func (r *ListenerSetReconciler) updateFailedStatus(ctx context.Context, ls *gatewayv1.ListenerSet, reason gatewayv1.ListenerSetConditionReason, msg string) (ctrl.Result, error) {
	now := metav1.Now()
	setListenerSetCondition(ls, metav1.Condition{
		Type:               string(gatewayv1.ListenerSetConditionAccepted),
		Status:             metav1.ConditionFalse,
		Reason:             string(reason),
		Message:            msg,
		ObservedGeneration: ls.GetGeneration(),
		LastTransitionTime: now,
	})
	setListenerSetCondition(ls, metav1.Condition{
		Type:               string(gatewayv1.ListenerSetConditionProgrammed),
		Status:             metav1.ConditionFalse,
		Reason:             string(gatewayv1.ListenerSetReasonInvalid),
		Message:            msg,
		ObservedGeneration: ls.GetGeneration(),
		LastTransitionTime: now,
	})

	ls.TypeMeta = metav1.TypeMeta{
		Kind:       KindListenerSet,
		APIVersion: gatewayv1.GroupVersion.String(),
	}
	_ = r.Provider.Delete(ctx, ls)

	r.Updater.Update(status.Update{
		NamespacedName: utils.NamespacedName(ls),
		Resource:       &gatewayv1.ListenerSet{},
		Mutator: status.MutatorFunc(func(obj client.Object) client.Object {
			target, ok := obj.(*gatewayv1.ListenerSet)
			if !ok {
				panic(fmt.Errorf("unsupported object type %T", obj))
			}
			targetCopy := target.DeepCopy()
			targetCopy.Status = ls.Status
			return targetCopy
		}),
	})
	return ctrl.Result{}, nil
}

func setListenerEntryCondition(lStatus *gatewayv1.ListenerEntryStatus, condType string, condStatus metav1.ConditionStatus, reason, message string, gen int64) {
	now := metav1.Now()
	for i, c := range lStatus.Conditions {
		if c.Type == condType {
			lStatus.Conditions[i].Status = condStatus
			lStatus.Conditions[i].Reason = reason
			lStatus.Conditions[i].Message = message
			lStatus.Conditions[i].ObservedGeneration = gen
			lStatus.Conditions[i].LastTransitionTime = now
			return
		}
	}
	lStatus.Conditions = append(lStatus.Conditions, metav1.Condition{
		Type:               condType,
		Status:             condStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: gen,
		LastTransitionTime: now,
	})
}

func setListenerSetCondition(ls *gatewayv1.ListenerSet, condition metav1.Condition) {
	for i, c := range ls.Status.Conditions {
		if c.Type == condition.Type {
			ls.Status.Conditions[i] = condition
			return
		}
	}
	ls.Status.Conditions = append(ls.Status.Conditions, condition)
}

func (r *ListenerSetReconciler) checkGatewayClass(gateway *gatewayv1.Gateway) bool {
	gatewayClass := &gatewayv1.GatewayClass{}
	if err := r.Get(context.Background(), client.ObjectKey{Name: string(gateway.Spec.GatewayClassName)}, gatewayClass); err != nil {
		r.Log.Error(err, "failed to get gateway class", "gateway", gateway.GetName(), "gatewayclass", gateway.Spec.GatewayClassName)
		return false
	}
	return matchesController(string(gatewayClass.Spec.ControllerName))
}

func (r *ListenerSetReconciler) collectPriorListeners(ctx context.Context, gw *gatewayv1.Gateway, currentLS *gatewayv1.ListenerSet) ([]gatewayv1.Listener, error) {
	var prior []gatewayv1.Listener
	// 1. Parent Gateway listeners have highest priority
	prior = append(prior, gw.Spec.Listeners...)

	// 2. Sibling ListenerSets with higher priority
	lsList := &gatewayv1.ListenerSetList{}
	if err := r.List(ctx, lsList); err != nil {
		return nil, err
	}

	for _, sibling := range lsList.Items {
		if sibling.Namespace == currentLS.Namespace && sibling.Name == currentLS.Name {
			continue
		}
		parentRef := sibling.Spec.ParentRef
		parentNs := sibling.Namespace
		if parentRef.Namespace != nil {
			parentNs = string(*parentRef.Namespace)
		}
		if parentNs != gw.Namespace || string(parentRef.Name) != gw.Name {
			continue
		}
		// Must be allowed
		allowed, err := isListenerSetAllowedByGateway(ctx, r.Client, gw, sibling.Namespace)
		if err != nil || !allowed {
			continue
		}
		// Check priority: older creationTimestamp wins, or alphabetical namespace/name
		if isHigherPriority(&sibling, currentLS) {
			for _, entry := range sibling.Spec.Listeners {
				prior = append(prior, ListenerFromEntry(entry))
			}
		}
	}

	return prior, nil
}

func isHigherPriority(a, b *gatewayv1.ListenerSet) bool {
	if a.CreationTimestamp.Before(&b.CreationTimestamp) {
		return true
	}
	if b.CreationTimestamp.Before(&a.CreationTimestamp) {
		return false
	}
	return (a.Namespace + "/" + a.Name) < (b.Namespace + "/" + b.Name)
}

func checkListenerConflict(entry gatewayv1.ListenerEntry, prior []gatewayv1.Listener) (bool, gatewayv1.ListenerEntryConditionReason) {
	for _, p := range prior {
		if entry.Port != p.Port {
			continue
		}
		if entry.Protocol != p.Protocol {
			return true, gatewayv1.ListenerEntryReasonProtocolConflict
		}
		if entry.Protocol == gatewayv1.TCPProtocolType || entry.Protocol == gatewayv1.UDPProtocolType {
			return true, gatewayv1.ListenerEntryReasonProtocolConflict
		}
		if isHostnameConflict(entry.Hostname, p.Hostname) {
			return true, gatewayv1.ListenerEntryReasonHostnameConflict
		}
	}
	return false, ""
}

func isHostnameConflict(h1, h2 *gatewayv1.Hostname) bool {
	s1 := ""
	if h1 != nil {
		s1 = strings.ToLower(string(*h1))
	}
	s2 := ""
	if h2 != nil {
		s2 = strings.ToLower(string(*h2))
	}
	if s1 == "" || s2 == "" {
		return true
	}
	return s1 == s2
}

func (r *ListenerSetReconciler) getAttachedRoutes(ctx context.Context, ls *gatewayv1.ListenerSet, entry gatewayv1.ListenerEntry) (int32, error) {
	listener := ListenerFromEntry(entry)
	fakeGateway := gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ls.Namespace,
			Name:      ls.Name,
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{listener},
		},
	}
	return getAttachedRoutesForListener(ctx, r.Client, fakeGateway, listener)
}

// Watch event mapper helpers

func (r *ListenerSetReconciler) listListenerSetsForGateway(ctx context.Context, obj client.Object) []reconcile.Request {
	gw, ok := obj.(*gatewayv1.Gateway)
	if !ok {
		return nil
	}
	lsList := &gatewayv1.ListenerSetList{}
	if err := r.List(ctx, lsList); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for _, ls := range lsList.Items {
		parentNs := ls.Namespace
		if ls.Spec.ParentRef.Namespace != nil {
			parentNs = string(*ls.Spec.ParentRef.Namespace)
		}
		if parentNs == gw.Namespace && string(ls.Spec.ParentRef.Name) == gw.Name {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ls.Namespace,
					Name:      ls.Name,
				},
			})
		}
	}
	return reqs
}

func (r *ListenerSetReconciler) listListenerSetsForGatewayClass(ctx context.Context, obj client.Object) []reconcile.Request {
	gc, ok := obj.(*gatewayv1.GatewayClass)
	if !ok || !matchesController(string(gc.Spec.ControllerName)) {
		return nil
	}
	lsList := &gatewayv1.ListenerSetList{}
	if err := r.List(ctx, lsList); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for _, ls := range lsList.Items {
		reqs = append(reqs, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: ls.Namespace,
				Name:      ls.Name,
			},
		})
	}
	return reqs
}

func (r *ListenerSetReconciler) listListenerSetsForRouteParent(ns, name string) []reconcile.Request {
	return []reconcile.Request{
		{
			NamespacedName: types.NamespacedName{
				Namespace: ns,
				Name:      name,
			},
		},
	}
}

func (r *ListenerSetReconciler) listListenerSetsForHTTPRoute(ctx context.Context, obj client.Object) []reconcile.Request {
	hr, ok := obj.(*gatewayv1.HTTPRoute)
	if !ok {
		return nil
	}
	var reqs []reconcile.Request
	for _, ref := range hr.Spec.ParentRefs {
		if ref.Kind != nil && *ref.Kind == KindListenerSet {
			ns := hr.Namespace
			if ref.Namespace != nil {
				ns = string(*ref.Namespace)
			}
			reqs = append(reqs, r.listListenerSetsForRouteParent(ns, string(ref.Name))...)
		}
	}
	return reqs
}

func (r *ListenerSetReconciler) listListenerSetsForGRPCRoute(ctx context.Context, obj client.Object) []reconcile.Request {
	gr, ok := obj.(*gatewayv1.GRPCRoute)
	if !ok {
		return nil
	}
	var reqs []reconcile.Request
	for _, ref := range gr.Spec.ParentRefs {
		if ref.Kind != nil && *ref.Kind == KindListenerSet {
			ns := gr.Namespace
			if ref.Namespace != nil {
				ns = string(*ref.Namespace)
			}
			reqs = append(reqs, r.listListenerSetsForRouteParent(ns, string(ref.Name))...)
		}
	}
	return reqs
}

func (r *ListenerSetReconciler) listListenerSetsForTCPRoute(ctx context.Context, obj client.Object) []reconcile.Request {
	tr, ok := obj.(*gatewayv1.TCPRoute)
	if !ok {
		return nil
	}
	var reqs []reconcile.Request
	for _, ref := range tr.Spec.ParentRefs {
		if ref.Kind != nil && *ref.Kind == KindListenerSet {
			ns := tr.Namespace
			if ref.Namespace != nil {
				ns = string(*ref.Namespace)
			}
			reqs = append(reqs, r.listListenerSetsForRouteParent(ns, string(ref.Name))...)
		}
	}
	return reqs
}

func (r *ListenerSetReconciler) listListenerSetsForTLSRoute(ctx context.Context, obj client.Object) []reconcile.Request {
	tr, ok := obj.(*gatewayv1.TLSRoute)
	if !ok {
		return nil
	}
	var reqs []reconcile.Request
	for _, ref := range tr.Spec.ParentRefs {
		if ref.Kind != nil && *ref.Kind == KindListenerSet {
			ns := tr.Namespace
			if ref.Namespace != nil {
				ns = string(*ref.Namespace)
			}
			reqs = append(reqs, r.listListenerSetsForRouteParent(ns, string(ref.Name))...)
		}
	}
	return reqs
}

func (r *ListenerSetReconciler) listListenerSetsForUDPRoute(ctx context.Context, obj client.Object) []reconcile.Request {
	ur, ok := obj.(*gatewayv1.UDPRoute)
	if !ok {
		return nil
	}
	var reqs []reconcile.Request
	for _, ref := range ur.Spec.ParentRefs {
		if ref.Kind != nil && *ref.Kind == KindListenerSet {
			ns := ur.Namespace
			if ref.Namespace != nil {
				ns = string(*ref.Namespace)
			}
			reqs = append(reqs, r.listListenerSetsForRouteParent(ns, string(ref.Name))...)
		}
	}
	return reqs
}

func (r *ListenerSetReconciler) listListenerSetsForSecret(ctx context.Context, obj client.Object) []reconcile.Request {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return nil
	}
	lsList := &gatewayv1.ListenerSetList{}
	if err := r.List(ctx, lsList); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for _, ls := range lsList.Items {
		matches := false
		for _, l := range ls.Spec.Listeners {
			if l.TLS != nil {
				for _, certRef := range l.TLS.CertificateRefs {
					ns := ls.Namespace
					if certRef.Namespace != nil {
						ns = string(*certRef.Namespace)
					}
					if ns == secret.Namespace && string(certRef.Name) == secret.Name {
						matches = true
						break
					}
				}
			}
			if matches {
				break
			}
		}
		if matches {
			reqs = append(reqs, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: ls.Namespace,
					Name:      ls.Name,
				},
			})
		}
	}
	return reqs
}

func (r *ListenerSetReconciler) listListenerSetsForReferenceGrant(ctx context.Context, obj client.Object) []reconcile.Request {
	rg, ok := obj.(*gatewayv1.ReferenceGrant)
	if !ok {
		return nil
	}
	lsList := &gatewayv1.ListenerSetList{}
	if err := r.List(ctx, lsList); err != nil {
		return nil
	}
	var reqs []reconcile.Request
	for _, ls := range lsList.Items {
		for _, from := range rg.Spec.From {
			if from.Group == gatewayv1.GroupName && from.Kind == KindListenerSet && string(from.Namespace) == ls.Namespace {
				reqs = append(reqs, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Namespace: ls.Namespace,
						Name:      ls.Name,
					},
				})
				break
			}
		}
	}
	return reqs
}
