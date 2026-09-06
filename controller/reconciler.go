package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// ActionRequest defines an incoming validated remediation decision payload.
type ActionRequest struct {
	Approved       bool   `json:"approved"`
	FinalAction    string `json:"final_action"`
	TargetPod      string `json:"target_pod"`
	Namespace      string `json:"namespace"`
	ProblemType    string `json:"problem_type"`
	MitreTechnique string `json:"mitre_technique,omitempty"`
	Reason         string `json:"reason"`
}

// ActionReconciler handles execution of validated actions on the Kubernetes cluster.
type ActionReconciler struct {
	KubeClient    kubernetes.Interface
	DynamicClient dynamic.Interface
}

func NewActionReconciler(client kubernetes.Interface, dynClient dynamic.Interface) *ActionReconciler {
	return &ActionReconciler{
		KubeClient:    client,
		DynamicClient: dynClient,
	}
}

// ReconcileAction executes the requested action if approved by Guardrails.
func (r *ActionReconciler) ReconcileAction(ctx context.Context, req ActionRequest) error {
	if !req.Approved {
		log.Printf("[GO-CONTROLLER SKIP] Action for pod %s skipped: not approved by guardrails (%s)", req.TargetPod, req.Reason)
		return nil
	}

	namespace := req.Namespace
	if namespace == "" {
		namespace = "default"
	}

	switch req.FinalAction {
	case "RESTART_POD":
		return r.handleRestartPod(ctx, namespace, req.TargetPod)
	case "SCALE_DEPLOYMENT":
		return r.handleScaleDeployment(ctx, namespace, req.TargetPod, 2)
	case "CILIUM_QUARANTINE_EBPF":
		return r.handleCiliumQuarantine(ctx, namespace, req.TargetPod, req.MitreTechnique)
	case "UNQUARANTINE_POD":
		return r.handleUnquarantinePod(ctx, namespace, req.TargetPod)
	case "ESCALATE":
		log.Printf("[GO-CONTROLLER ESCALATE] Pod %s escalated to human operator", req.TargetPod)
		return nil
	default:
		return fmt.Errorf("unsupported action type: %s", req.FinalAction)
	}
}

func (r *ActionReconciler) handleRestartPod(ctx context.Context, namespace, targetPod string) error {
	log.Printf("[GO-CONTROLLER EXECUTE] Deleting pod %s in namespace %s to trigger restart", targetPod, namespace)
	err := r.KubeClient.CoreV1().Pods(namespace).Delete(ctx, targetPod, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete pod %s: %v", targetPod, err)
	}
	log.Printf("[GO-CONTROLLER SUCCESS] Pod %s successfully deleted for restart", targetPod)
	return nil
}

func resolveDeploymentName(targetPod string) string {
	parts := strings.Split(targetPod, "-")
	if len(parts) >= 3 {
		if len(parts[len(parts)-2]) >= 8 {
			return strings.Join(parts[:len(parts)-2], "-")
		}
		return strings.Join(parts[:len(parts)-1], "-")
	} else if len(parts) == 2 {
		return parts[0]
	}
	return targetPod
}

func (r *ActionReconciler) handleScaleDeployment(ctx context.Context, namespace, targetPod string, replicas int32) error {
	deploymentName := resolveDeploymentName(targetPod)
	log.Printf("[GO-CONTROLLER EXECUTE] Scaling deployment %s in namespace %s to %d replicas", deploymentName, namespace, replicas)

	scale, err := r.KubeClient.AppsV1().Deployments(namespace).GetScale(ctx, deploymentName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get scale for deployment %s: %v", deploymentName, err)
	}

	scale.Spec.Replicas = replicas
	_, err = r.KubeClient.AppsV1().Deployments(namespace).UpdateScale(ctx, deploymentName, scale, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update scale for deployment %s: %v", deploymentName, err)
	}
	log.Printf("[GO-CONTROLLER SUCCESS] Deployment %s scaled to %d replicas", deploymentName, replicas)
	return nil
}

func (r *ActionReconciler) handleCiliumQuarantine(ctx context.Context, namespace, targetPod, mitreTTP string) error {
	log.Printf("[GO-CONTROLLER EXECUTE] Creating CiliumNetworkPolicy eBPF quarantine for pod %s (MITRE: %s)", targetPod, mitreTTP)

	ciliumGVR := schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumnetworkpolicies",
	}

	policy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "cilium.io/v2",
			"kind":       "CiliumNetworkPolicy",
			"metadata": map[string]interface{}{
				"name":      fmt.Sprintf("aegis-quarantine-%s", targetPod),
				"namespace": namespace,
				"labels": map[string]interface{}{
					"aegis.io/quarantine": "true",
					"app.kubernetes.io/managed-by": "aegis-sre",
					"target-pod": targetPod,
				},
				"annotations": map[string]interface{}{
					"aegis.io/mitre-ttp": mitreTTP,
					"aegis.io/status":    "QUARANTINED",
				},
			},
			"spec": map[string]interface{}{
				"endpointSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"io.kubernetes.pod.name": targetPod,
					},
				},
				"ingress": []interface{}{},
				"egress":  []interface{}{},
			},
		},
	}

	_, err := r.DynamicClient.Resource(ciliumGVR).Namespace(namespace).Create(ctx, policy, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create CiliumNetworkPolicy for %s: %v", targetPod, err)
	}

	log.Printf("[GO-CONTROLLER SUCCESS] Applied eBPF CiliumNetworkPolicy for pod %s", targetPod)
	return nil
}

func (r *ActionReconciler) handleUnquarantinePod(ctx context.Context, namespace, targetPod string) error {
	log.Printf("[GO-CONTROLLER EXECUTE] Deleting CiliumNetworkPolicy eBPF quarantine for pod %s", targetPod)
	policyName := fmt.Sprintf("aegis-quarantine-%s", targetPod)

	ciliumGVR := schema.GroupVersionResource{
		Group:    "cilium.io",
		Version:  "v2",
		Resource: "ciliumnetworkpolicies",
	}

	err := r.DynamicClient.Resource(ciliumGVR).Namespace(namespace).Delete(ctx, policyName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete CiliumNetworkPolicy %s: %v", policyName, err)
	}

	log.Printf("[GO-CONTROLLER SUCCESS] Removed eBPF CiliumNetworkPolicy %s. Pod traffic restored.", policyName)
	return nil
}
