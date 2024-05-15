# opa
Open Policy Agent on Dockers and Kubernetes

#OPA on Docker

//Start the OPA server with policy file using the following command

opa run --server docker.rego

//Once OPA server is running , run the main.go file

go run main.go

//Once the Go application is running, user can access the following API endpoints using Postman

To retrieve existing policies: GET http://localhost:8080/policies

To add a new policy: POST http://localhost:8080/policies with a JSON payload containing the policy details.

To delete a policy: DELETE http://localhost:8080/policies/{name}

To run a Docker container with a specific image: GET http://localhost:8080/run/{imageName}

#OPA on Kubernetes

//Run the following command to evaluate your policy with the input

opa eval --data policy.rego --input input.json "data.kubernetes.admission"

//Command to run the golang file

go run main.go

