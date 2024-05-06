package kubernetes.admission

allow {
    starts_with(input.request.object.metadata.name, "platform")
}

deny[msg] {
    not allow
    msg := "Pod name must start with 'platform'"
}
