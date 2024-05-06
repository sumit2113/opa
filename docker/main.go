package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/gorilla/mux"
)

var (
	dockerRWMutex  sync.RWMutex
	dockerRegoFile = "docker.rego"
)

type Policy struct {
	Name string `json:"name"`
	Rule string `json:"rule"`
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/policies", getPoliciesHandler).Methods("GET")
	r.HandleFunc("/policies", addPolicyHandler).Methods("POST")
	r.HandleFunc("/policies/{name}", deletePolicyHandler).Methods("DELETE")
	r.HandleFunc("/run/{imageName}", runDockerContainer).Methods("GET")

	fmt.Println("Server listening on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func getPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	dockerRWMutex.RLock()
	defer dockerRWMutex.RUnlock()

	content, err := ioutil.ReadFile(dockerRegoFile)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read %s: %s", dockerRegoFile, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(content)
}

func addPolicyHandler(w http.ResponseWriter, r *http.Request) {
	var newPolicy Policy
	err := json.NewDecoder(r.Body).Decode(&newPolicy)
	if err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	dockerRWMutex.Lock()
	defer dockerRWMutex.Unlock()

	content, err := ioutil.ReadFile(dockerRegoFile)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read %s: %s", dockerRegoFile, err), http.StatusInternalServerError)
		return
	}

	content = append(content, []byte(fmt.Sprintf("\n%s = %q", newPolicy.Name, newPolicy.Rule))...)

	err = ioutil.WriteFile(dockerRegoFile, content, 0644)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to write %s: %s", dockerRegoFile, err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func deletePolicyHandler(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	name := params["name"]

	dockerRWMutex.Lock()
	defer dockerRWMutex.Unlock()

	content, err := ioutil.ReadFile(dockerRegoFile)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read %s: %s", dockerRegoFile, err), http.StatusInternalServerError)
		return
	}

	updatedContent := []byte{}
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if !strings.Contains(line, name) {
			updatedContent = append(updatedContent, []byte(line+"\n")...)
		}
	}

	err = ioutil.WriteFile(dockerRegoFile, updatedContent, 0644)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to write %s: %s", dockerRegoFile, err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func queryOPA(imageName string) (bool, error) {
	input := map[string]interface{}{
		"input": map[string]interface{}{
			"docker_image": map[string]interface{}{
				"name": imageName,
			},
		},
	}

	inputBytes, err := json.Marshal(input)
	if err != nil {
		return false, err
	}

	response, err := http.Post("http://localhost:8181/v1/data/main/docker/allow", "application/json", bytes.NewBuffer(inputBytes))
	if err != nil {
		return false, err
	}
	defer response.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return false, err
	}

	allowed, found := result["result"].(bool)
	if !found {
		return false, fmt.Errorf("policy evaluation did not return a boolean result")
	}

	return allowed, nil
}

func runDockerContainer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	imageName := vars["imageName"]

	allowed, err := queryOPA(imageName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !allowed {
		http.Error(w, "Policy violation: Image not allowed", http.StatusForbidden)
		return
	}

	cmd := exec.Command("docker", "run", "--rm", "-d", imageName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Container running with image %s", imageName)
}
