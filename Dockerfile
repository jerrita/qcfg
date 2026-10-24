FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /qcfg ./cmd/qcfg
RUN mkdir /data

FROM scratch
COPY --from=build /qcfg /qcfg
COPY --from=build --chown=65532:65532 /data /data
USER 65532:65532
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/qcfg", "serve", "--data", "/data", "--listen", ":8080"]
