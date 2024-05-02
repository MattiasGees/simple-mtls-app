.DEFAULT_GOAL := build

IMAGE_SERVER ?= mattiasgees/simple-mtls-server:latest
IMAGE_CLIENT ?= mattiasgees/simple-mtls-client:latest

export DOCKER_CLI_EXPERIMENTAL=enabled

.PHONY: build # Build the container image
build:
	@docker buildx create --use --name=crossplat --node=crossplat && \
	docker buildx build \
		--output "type=docker,push=false" \
		--tag $(IMAGE_SERVER) \
		--tag Dockerfile.server \
		.
	docker buildx build \
		--output "type=docker,push=false" \
		--tag $(IMAGE_CLIENT) \
		--tag Dockerfile.client \
		.

.PHONY: publish # Push all the image to the remote registry
publish:
	@docker buildx create --use --name=crossplat --node=crossplat && \
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--output "type=image,push=true" \
		--tag $(IMAGE_SERVER) \
		--file Dockerfile.server \
		.
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--output "type=image,push=true" \
		--tag $(IMAGE_CLIENT) \
		--file Dockerfile.client \
		.

.PHONY: publish-server # Push the Server image to the remote registry
publish-server:
	@docker buildx create --use --name=crossplat --node=crossplat && \
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--output "type=image,push=true" \
		--tag $(IMAGE_SERVER) \
		--file Dockerfile.server \
		.

.PHONY: publish-client # Push the Server image to the remote registry
publish-client:
	@docker buildx create --use --name=crossplat --node=crossplat && \
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--output "type=image,push=true" \
		--tag $(IMAGE_CLIENT) \
		--file Dockerfile.client \
		.
