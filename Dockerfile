# Build the static binary first: CGO_ENABLED=0 go build -trimpath -o bin/probe ./cmd/probe
FROM scratch
COPY --chmod=0555 bin/probe /probe
USER 65532:65532
EXPOSE 4899/tcp 4899/udp
ENTRYPOINT ["/probe"]
