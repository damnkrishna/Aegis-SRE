package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	log.Println("Starting Aegis-SRE Go Action Controller Service (Phase 5)...")

	var reconciler *ActionReconciler
	config, err := getKubeConfig()
	if err != nil {
		log.Printf("Warning: Unable to load kubeconfig (running in offline/dry-run mode): %v", err)
		reconciler = NewActionReconciler(nil, nil)
	} else {
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			log.Printf("Error creating kubernetes clientset (falling back to dry-run): %v", err)
		}
		dynClient, err := dynamic.NewForConfig(config)
		if err != nil {
			log.Printf("Error creating dynamic client (falling back to dry-run): %v", err)
		}
		reconciler = NewActionReconciler(clientset, dynClient)
		log.Println("Aegis-SRE Go Controller connected successfully to K8s cluster API.")
	}

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "service": "aegis-go-controller"})
	})

	http.HandleFunc("/api/v1/reconcile", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		var req ActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"Invalid JSON payload: %v"}`, err), http.StatusBadRequest)
			return
		}

		log.Printf("[GO-CONTROLLER INGEST] Received Action Request: Action=%s Target=%s Approved=%t", req.FinalAction, req.TargetPod, req.Approved)

		if reconciler.KubeClient == nil {
			log.Printf("[GO-CONTROLLER DRY-RUN EXECUTE] Simulated %s on pod %s (Reason: %s)", req.FinalAction, req.TargetPod, req.Reason)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":    "success",
				"mode":      "dry_run",
				"action":    req.FinalAction,
				"target":    req.TargetPod,
				"message":   "Executed in Go Controller Dry-Run Mode",
			})
			return
		}

		err := reconciler.ReconcileAction(context.Background(), req)
		if err != nil {
			log.Printf("[GO-CONTROLLER ERROR] Reconcile failed for %s: %v", req.TargetPod, err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "error",
				"error":   err.Error(),
				"target":  req.TargetPod,
			})
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "success",
			"mode":    "k8s_cluster",
			"action":  req.FinalAction,
			"target":  req.TargetPod,
			"message": "Executed successfully via client-go K8s API",
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Go Controller listening for reconcile requests on :%s...", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Go Controller server failed: %v", err)
	}
}

func getKubeConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err == nil {
		return config, nil
	}

	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		homeDir, _ := os.UserHomeDir()
		kubeconfig = fmt.Sprintf("%s/.kube/config", homeDir)
	}

	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}
