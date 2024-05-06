package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/open-policy-agent/opa/rego"
	"k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var (
	port             int
	policyPath       string
	policyDefinition rego.PreparedEvalQuery
)

func init() {
	flag.IntVar(&port, "port", 8080, "Port to listen on")
	flag.StringVar(&policyPath, "policy", "k8s.rego", "Path to policy file")
}

func main() {
	flag.Parse()

	// Load policy
	policy, err := ioutil.ReadFile(policyPath)
	if err != nil {
		log.Fatalf("failed to read policy file: %v", err)
	}

	ctx := context.Background()
	policyDefinition, err = rego.New(
		rego.Query("data.kubernetes.admission.allow"),
		rego.Module("k8s.rego", string(policy)),
	).PrepareForEval(ctx)
	if err != nil {
		log.Fatalf("failed to prepare policy definition: %v", err)
	}

	// Create HTTP server
	http.HandleFunc("/admit", admitHandler)
	log.Printf("Starting admission controller on port %d", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}

func admitHandler(w http.ResponseWriter, r *http.Request) {
	// Read admission review request
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	// Parse admission review request
	var reviewReq v1.AdmissionReview
	if err := json.Unmarshal(body, &reviewReq); err != nil {
		http.Error(w, "failed to unmarshal admission review request", http.StatusBadRequest)
		return
	}

	// Call admission control function
	reviewResp := admitPodCreation(reviewReq)

	// Write admission review response
	respBody, err := json.Marshal(reviewResp)
	if err != nil {
		http.Error(w, "failed to marshal admission review response", http.StatusInternalServerError)
		return
	}

	if _, err := w.Write(respBody); err != nil {
		http.Error(w, "failed to write response", http.StatusInternalServerError)
		return
	}
}

func admitPodCreation(review v1.AdmissionReview) *v1.AdmissionReview {
	req := review.Request

	var obj runtime.RawExtension
	if err := json.Unmarshal(req.Object.Raw, &obj); err != nil {
		return toAdmissionResponse(review, fmt.Errorf("failed to unmarshal pod: %v", err))
	}

	// Prepare input for policy evaluation
	input := map[string]interface{}{
		"request": map[string]interface{}{
			"namespace": req.Namespace,
			"operation": req.Operation,
			"object":    obj.Object,
		},
	}

	// Evaluate policy
	resultSet, err := policyDefinition.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		return toAdmissionResponse(review, fmt.Errorf("policy evaluation error: %v", err))
	}

	// Extract decision from policy evaluation result
	decision := false
	if len(resultSet) > 0 {
		decision, _ = resultSet[0].Bindings["allow"].(bool)
	}

	// Formulate admission review response
	status := &v1.AdmissionResponse{
		Allowed: decision,
	}

	if decision {
		status.Result = &metav1.Status{
			Status:  metav1.StatusSuccess,
			Message: "Allowed by policy",
		}
	} else {
		status.Result = &metav1.Status{
			Status: metav1.StatusFailure,
			Message: "Denied by policy",
			Reason: metav1.StatusReasonForbidden,
			Details: &metav1.StatusDetails{
				Causes: []metav1.StatusCause{
					{Type: "PolicyViolation", Message: "Pod creation denied by policy"},
				},
			},
		}
	}

	return &v1.AdmissionReview{
		Response: status,
	}
}

func toAdmissionResponse(review v1.AdmissionReview, err error) *v1.AdmissionReview {
	status := &v1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Status: metav1.StatusFailure,
			Message: err.Error(),
		},
	}

	return &v1.AdmissionReview{
		Response: status,
	}
}
