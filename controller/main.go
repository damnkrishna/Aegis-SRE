package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	log.Println("Starting Aegis-SRE Go Action Controller (Phase 5)...")

	config, err := getKubeConfig()
	if err != nil {
		log.Printf("Warning: Unable to load kubeconfig (running in offline/dry-run mode): %v", err)
	} else {
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			log.Fatalf("Error creating kubernetes clientset: %v", err)
		}

		dynClient, err := dynamic.NewForConfig(config)
		if err != nil {
			log.Fatalf("Error creating dynamic client: %v", err)
		}

		reconciler := NewActionReconciler(clientset, dynClient)
		log.Println("Aegis-SRE Go Controller initialized successfully and connected to K8s cluster.")

		_ = reconciler.ReconcileAction(context.Background(), ActionRequest{
			Approved:       true,
			FinalAction:    "CILIUM_QUARANTINE_EBPF",
			TargetPod:      "sample-app",
			Namespace:      "default",
			ProblemType:    "SECURITY_ATTACK",
			MitreTechnique: "T1059",
			Reason:         "Falco shell spawn alert detected",
		})
	}
}

func getKubeConfig() (*rest.Config, error) {
	// Try in-cluster config first
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}

	// Fallback to KUBECONFIG env var or default ~/.kube/config
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		homeDir, _ := os.UserHomeDir()
		kubeconfig = fmt.Sprintf("%s/.kube/config", homeDir)
	}

	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}
