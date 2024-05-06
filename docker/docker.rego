package main.docker

default allow = false

# Allows running Docker containers only if the image name starts with "platform"
allow {
    startswith(input.docker_image.name, "platform")
}
