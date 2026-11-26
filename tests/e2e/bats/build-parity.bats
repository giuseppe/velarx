# SPDX-License-Identifier: Apache-2.0
# The options of pull, run and build that podman has and velarx got for
# parity: --pull=newer compares digests and tolerates a registry that does
# not answer, --retry tries 3 times by default, the platform arguments of a
# build (TARGETARCH, BUILDPLATFORM...), and build --jobs.  Through a daemon of
# its own.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/build-parity.bats

load helpers
load run_lib

setup_file () {
    run_setup_file
    export REPO=$E2E_REGISTRY/velarx-e2e/build-parity-$$
}

teardown_file () {
    run_teardown_file
}

teardown () {
    run_test_teardown
}

host_arch () {
    case $(uname -m) in
    x86_64) echo amd64 ;;
    aarch64) echo arm64 ;;
    *) uname -m ;;
    esac
}

@test "build: the platform arguments" {
    local arch ctx=$WORKDIR/pctx
    arch=$(host_arch)
    mkdir -p "$ctx"
    cat > "$ctx/Containerfile" <<EOT
ARG BUILDPLATFORM=not-a-platform
FROM --platform=\$BUILDPLATFORM $IMAGE AS p
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT=a-default-does-not-change-it
ARG BUILDOS
ARG BUILDARCH
ARG BUILDVARIANT
ARG BUILDPLATFORM
ARG NOTPREDEFINED
LABEL t="\$TARGETPLATFORM" o="\$TARGETOS" a="\$TARGETARCH" v="[\$TARGETVARIANT]" bo="\$BUILDOS" ba="\$BUILDARCH" bv="[\$BUILDVARIANT]" bp="\$BUILDPLATFORM" n="[\$NOTPREDEFINED]"
FROM p
LABEL i="\$TARGETARCH"
EOT
    sh_ image build -q -t localhost/e2e-pargs:1 "$ctx" > /dev/null
    check "build" 0 $?
    label () { sh_ image inspect -f "{{index .Config.Labels \"$1\"}}" localhost/e2e-pargs:1; }
    check "TARGETPLATFORM" "linux/$arch" "$(label t)"
    check "TARGETOS" linux "$(label o)"
    check "TARGETARCH" "$arch" "$(label a)"
    check "TARGETVARIANT is empty" "[]" "$(label v)"
    check "BUILDOS" linux "$(label bo)"
    check "BUILDARCH" "$arch" "$(label ba)"
    check "BUILDPLATFORM" "linux/$arch" "$(label bp)"
    check "a name that is not predefined is empty" "[]" "$(label n)"
    check "a stage FROM a stage has its arguments" "$arch" "$(label i)"
    sh_ image build -q --build-arg TARGETARCH=riscv64 -t localhost/e2e-pargs:2 "$ctx" > /dev/null
    check "a --build-arg overrides" riscv64 "$(sh_ image inspect -f '{{index .Config.Labels "a"}}' localhost/e2e-pargs:2)"
    sh_ rmi localhost/e2e-pargs:1 localhost/e2e-pargs:2 > /dev/null 2>&1
}

@test "pull --policy=newer: the same image is not pulled again" {
    sh_ image pull -q "$IMAGE" > /dev/null
    id=$(sh_ image inspect -f '{{.Id}}' "$IMAGE")
    out=$(sh_ image pull --policy=newer "$IMAGE" 2>&1)
    check "pull" 0 $?
    check "prints the id and nothing else" "$id" "$out"
    out=$(sh_ container create --pull=newer --name e2e-newer "$IMAGE" true 2>&1)
    check "create --pull=newer" 0 $?
    check "...pulls nothing" 0 "$(echo "$out" | grep -c "Trying to pull")"
    sh_ container rm e2e-newer > /dev/null
}

@test "pull --policy=newer: another image of the registry is pulled" {
    local ctx=$WORKDIR/nctx
    mkdir -p "$ctx"
    sh_ image tag "$IMAGE" "$REPO:n"
    sh_ image push "$REPO:n" > /dev/null 2>&1
    sh_ image rm "$REPO:n" > /dev/null
    sh_ image pull -q "$REPO:n" > /dev/null
    old=$(sh_ image inspect -f '{{.Id}}' "$REPO:n")
    printf 'FROM %s\nLABEL changed=1\n' "$IMAGE" > "$ctx/Containerfile"
    sh_ image build -q -t "$REPO:n2" "$ctx" > /dev/null
    sh_ image push "$REPO:n2" "$REPO:n" > /dev/null 2>&1
    check "push of the other image" 0 $?
    out=$(sh_ image pull --policy=newer "$REPO:n" 2>&1)
    check "pull --policy=newer" 0 $?
    check_match "the other image" "$(sh_ image inspect -f '{{.Id}}' "$REPO:n2")" "$out"
    [ "$old" != "$(sh_ image inspect -f '{{.Id}}' "$REPO:n")" ]
    check "the name is the new image" 0 $?
    sh_ rmi "$REPO:n" "$REPO:n2" > /dev/null 2>&1
}

@test "pull --policy=newer: a registry that does not answer is the local image" {
    sh_ image tag "$IMAGE" localhost:1/e2e/down:1
    out=$(sh_ image pull --policy=newer --tls-verify=false --retry 0 localhost:1/e2e/down:1 2>&1)
    check "pull of an image whose registry is down" 0 $?
    check "...the local id" "$(sh_ image inspect -f '{{.Id}}' "$IMAGE")" "$out"
    out=$(sh_ image pull --policy=always --tls-verify=false --retry 0 localhost:1/e2e/down:1 2>&1)
    check "always fails" 125 $?
    sh_ image rm localhost:1/e2e/down:1 > /dev/null
}

@test "build --pull=newer" {
    local ctx=$WORKDIR/bnctx
    mkdir -p "$ctx"
    sh_ image pull -q "$IMAGE" > /dev/null
    printf 'FROM %s\nLABEL a=1\n' "$IMAGE" > "$ctx/Containerfile"
    out=$(sh_ image build --pull=newer -q -t localhost/e2e-bnewer:1 "$ctx" 2>&1)
    check "build --pull=newer with an image that is current" 0 $?
    check "...pulls nothing" 0 "$(echo "$out" | grep -c "^Pulling")"
    sh_ image tag "$IMAGE" localhost:1/e2e/down:2
    printf 'FROM localhost:1/e2e/down:2\nLABEL a=2\n' > "$ctx/Containerfile"
    sh_ image build --pull=newer --tls-verify=false --retry 0 -q -t localhost/e2e-bnewer:2 "$ctx" > /dev/null 2>&1
    check "a registry that is down: the local base" 0 $?
    sh_ rmi localhost/e2e-bnewer:1 localhost/e2e-bnewer:2 localhost:1/e2e/down:2 > /dev/null 2>&1
}

@test "--retry defaults to 3, only for what may pass" {
    out=$(sh_ image pull --tls-verify=false localhost:1/e2e/nosuch:1 2>&1)
    check "pull" 125 $?
    check_match "the default is 3 tries" "retrying in 1s ... \\(1/3\\)" "$out"
    check_match "the last of them, 1s apart as podman's" "retrying in 1s ... \\(3/3\\)" "$out"
    out=$(sh_ image pull --tls-verify=false --retry 0 localhost:1/e2e/nosuch:1 2>&1)
    check "--retry 0 tries once" 0 "$(echo "$out" | grep -c retrying)"
    out=$(sh_ image pull --tls-verify=false --retry 1 --retry-delay 100ms localhost:1/e2e/nosuch:1 2>&1)
    check_match "--retry-delay" "retrying in 100ms ... \\(1/1\\)" "$out"
}

@test "build --jobs: independent stages run at the same time" {
    local ctx=$WORKDIR/jctx s0 s1 out
    mkdir -p "$ctx"
    cat > "$ctx/Containerfile" <<EOT
FROM $IMAGE AS one
RUN echo one-start && sleep 4 && echo one-end > /one
FROM $IMAGE AS two
RUN echo two-start && sleep 4 && echo two-end > /two
FROM $IMAGE AS three
COPY --from=one /one /one
RUN echo three-start
FROM $IMAGE
COPY --from=three /one /one
COPY --from=two /two /two
RUN cat /one /two > /both
EOT
    s0=$(date +%s)
    sh_ image build -q --no-cache -t localhost/e2e-jobs:1 "$ctx" > /dev/null 2>&1
    check "build with --jobs 1" 0 $?
    s1=$(date +%s)
    seq=$((s1 - s0))
    [ "$seq" -ge 8 ]
    check "the stages one after the other take their sum" 0 $?
    s0=$(date +%s)
    out=$(sh_ image build --jobs 0 --no-cache -t localhost/e2e-jobs:2 "$ctx" 2>&1)
    check "build with --jobs 0" 0 $?
    s1=$(date +%s)
    [ $((s1 - s0)) -lt "$seq" ]
    check "...takes less" 0 $?
    check "the same image content" "one-end two-end" "$(sh_ container run --rm localhost/e2e-jobs:2 cat /both | tr '\n' ' ' | sed 's/ $//')"
    # the log is the one of the stages one after the other
    check "the steps are numbered as they are" "one-start two-start three-start" \
        "$(echo "$out" | grep -E '^(one|two|three)-start$' | tr '\n' ' ' | sed 's/ $//')"
    check_match "the stages are in order" "\\[4/4\\] STEP 1/4: FROM" "$out"
    printf 'FROM %s AS a\nRUN sleep 60 && echo a-ran\nFROM %s AS b\nRUN echo b-fails && false\nFROM %s\nCOPY --from=a /etc/hostname /a\nCOPY --from=b /etc/hostname /b\n' \
        "$IMAGE" "$IMAGE" "$IMAGE" > "$ctx/Containerfile"
    s0=$(date +%s)
    out=$(sh_ image build --jobs 2 --no-cache -t localhost/e2e-jobs:3 "$ctx" 2>&1)
    check "a stage that fails fails the build" 125 $?
    [ $(($(date +%s) - s0)) -lt 30 ]
    check "...and stops the stages that run" 0 $?
    check_match "...says which step" "b-fails" "$out"
    sh_ rmi localhost/e2e-jobs:1 localhost/e2e-jobs:2 > /dev/null 2>&1
}

@test "build -f: a pipe is the Containerfile" {
    local ctx=$WORKDIR/fctx
    mkdir -p "$ctx"
    sh_ image build -q -t localhost/e2e-fpipe:1 -f <(printf 'FROM %s\nLABEL from=pipe\n' "$IMAGE") "$ctx" > /dev/null
    check "build with -f <(...)" 0 $?
    check "the Containerfile of the pipe" pipe "$(sh_ image inspect -f '{{index .Config.Labels "from"}}' localhost/e2e-fpipe:1)"
    printf 'LABEL second=yes\n' > "$ctx/second"
    sh_ image build -q -t localhost/e2e-fpipe:2 -f <(printf 'FROM %s\n' "$IMAGE") -f "$ctx/second" "$ctx" > /dev/null
    check "a pipe among several -f" 0 $?
    check "...is one Containerfile with the others" yes "$(sh_ image inspect -f '{{index .Config.Labels "second"}}' localhost/e2e-fpipe:2)"
    sh_ rmi localhost/e2e-fpipe:1 localhost/e2e-fpipe:2 > /dev/null 2>&1
}

@test "build: --platform and --output may be given again" {
    local ctx=$WORKDIR/mctx
    mkdir -p "$ctx"
    printf 'FROM scratch\nCOPY f /f\n' > "$ctx/Containerfile"
    echo x > "$ctx/f"
    sh_ image build --platform linux/amd64 --platform linux/arm64 --logfile "$ctx/log" --logsplit "$ctx" > /dev/null
    check "build with --platform twice" 0 $?
    for p in amd64 arm64; do
        check_match "a build for $p" "COPY f /f" "$(cat "$ctx/log_linux_$p")"
    done
    sh_ image build -q -o "$WORKDIR/out-dir" -o "type=tar,dest=$WORKDIR/out.tar" "$ctx" > /dev/null
    check "build with -o twice" 0 $?
    check "the directory" x "$(cat "$WORKDIR/out-dir/f")"
    check "the tar" f "$(tar -tf "$WORKDIR/out.tar" | grep -x f)"
    out=$(sh_ image build -q -o - -o type=tar,dest=- "$ctx" 2>&1 > /dev/null)
    check "two tars on the standard output" 125 $?
    check_match "...are refused" "only one --output may be the standard output" "$out"
}

@test "build: --compression-format, --compression-level and --force-compression are checked and change nothing" {
    local ctx=$WORKDIR/cctx
    mkdir -p "$ctx"
    printf 'FROM scratch\nCOPY f /f\n' > "$ctx/Containerfile"
    echo x > "$ctx/f"
    sh_ image build -q --compression-format zstd:chunked --compression-level 3 --force-compression -t localhost/e2e-comp:1 "$ctx" > /dev/null
    check "build with the compression options" 0 $?
    sh_ image build -q --compression-format gzip --force-compression=false -t localhost/e2e-comp:2 "$ctx" > /dev/null
    check "build with gzip" 0 $?
    out=$(sh_ image build -q --compression-format lz4 -t localhost/e2e-comp:3 "$ctx" 2>&1)
    check "an unknown format" 125 $?
    check_match "...is named" "invalid compression .lz4." "$out"
    out=$(sh_ image build -q --compression-level x -t localhost/e2e-comp:3 "$ctx" 2>&1)
    check "a level that is no number" 125 $?
    sh_ rmi localhost/e2e-comp:1 localhost/e2e-comp:2 > /dev/null 2>&1
}

@test "build --iidfile-raw and --metadata-file" {
    local ctx=$WORKDIR/metactx raw=$WORKDIR/iid-raw meta=$WORKDIR/meta.json iid=$WORKDIR/iid
    mkdir -p "$ctx"
    printf 'FROM %s\nLABEL m=1\n' "$IMAGE" > "$ctx/Containerfile"
    out=$(sh_ image build -q --iidfile-raw "$raw" --iidfile "$iid" --metadata-file "$meta" -t localhost/e2e-meta:1 "$ctx" 2> /dev/null)
    check "build" 0 $?
    check "the id is in the files, not on the standard output" "" "$out"
    check_match "the raw id has no algorithm" "^[0-9a-f]{64}$" "$(cat "$raw")"
    check "the id file has it" "sha256:$(cat "$raw")" "$(cat "$iid")"
    check "the id is the image's" "$(sh_ image inspect -f '{{.Id}}' localhost/e2e-meta:1)" "$(cat "$raw")"
    check "the config digest" "sha256:$(cat "$raw")" "$(jq -r '."containerimage.config.digest"' "$meta")"
    digest=$(sh_ image inspect -f '{{.Digest}}' localhost/e2e-meta:1)
    check "the manifest digest" "$digest" "$(jq -r '."containerimage.digest"' "$meta")"
    check "the descriptor digest" "$digest" "$(jq -r '."containerimage.descriptor".digest' "$meta")"
    check "the descriptor media type" "application/vnd.oci.image.manifest.v1+json" "$(jq -r '."containerimage.descriptor".mediaType' "$meta")"
    check_match "the descriptor size" "^[1-9][0-9]*$" "$(jq -r '."containerimage.descriptor".size' "$meta")"
    # with --manifest the image the build added to the list
    sh_ image build -q --manifest localhost/e2e-meta-list --metadata-file "$meta" "$ctx" > /dev/null 2>&1
    check "build --manifest" 0 $?
    check "...the digest of the image" "$digest" "$(jq -r '."containerimage.digest"' "$meta")"
    # several images: one id is written, the metadata is refused
    rm "$raw"
    rc=0
    sh_ image build -q --iidfile-raw "$raw" --platform linux/amd64,linux/arm64 "$ctx" > /dev/null 2>&1 || rc=$?
    check "several platforms with --iidfile-raw" 0 $rc
    check_match "...write an id" "^[0-9a-f]{64}$" "$(cat "$raw")"
    rc=0
    sh_ image build --metadata-file "$WORKDIR/none" --platform linux/amd64,linux/arm64 "$ctx" > /dev/null 2> "$WORKDIR/err" || rc=$?
    check "several platforms with --metadata-file" 125 $rc
    check_match "...say why" "building multiple images, but metadata file .* can only be used to store information about one image" "$(cat "$WORKDIR/err")"
    check "...and write nothing" "no" "$([ -e "$WORKDIR/none" ] && echo yes || echo no)"
    sh_ manifest rm localhost/e2e-meta-list > /dev/null 2>&1
    sh_ rmi localhost/e2e-meta:1 > /dev/null 2>&1
}

@test "buildx build and builder build are build" {
    local ctx=$WORKDIR/bxctx
    mkdir -p "$ctx"
    printf 'FROM scratch\nLABEL via=x\n' > "$ctx/Containerfile"
    for group in buildx builder; do
        sh_ "$group" build -q -t localhost/e2e-bx:$group "$ctx" > /dev/null
        check "$group build" 0 $?
        check "the image of $group build" x "$(sh_ image inspect -f '{{index .Config.Labels "via"}}' localhost/e2e-bx:$group)"
    done
    sh_ rmi localhost/e2e-bx:buildx localhost/e2e-bx:builder > /dev/null 2>&1
}

@test "build --save-stages and --stage-labels" {
    local ctx=$WORKDIR/sctx stage_ids
    mkdir -p "$ctx"
    printf 'FROM %s AS first\nLABEL a=1\nFROM first AS second\nLABEL b=2\nFROM second\nLABEL c=3\n' "$IMAGE" > "$ctx/Containerfile"
    rc=0
    out=$(sh_ image build -q --stage-labels -t localhost/e2e-stages:1 "$ctx" 2>&1) || rc=$?
    check "--stage-labels alone" 125 $rc
    check_match "...is refused" "requires --save-stages" "$out"
    local before
    before=$(sh_ image list -a -q | wc -l)
    sh_ image build -q --layers=false -t localhost/e2e-stages:1 "$ctx" > /dev/null
    check "build" 0 $?
    check "no image of a stage stays" $((before + 1)) "$(sh_ image list -a -q | wc -l)"
    sh_ image build -q --layers=false --save-stages --stage-labels -t localhost/e2e-stages:2 "$ctx" > /dev/null
    check "build --save-stages --stage-labels" 0 $?
    check "the built image is the stage 2" 2 "$(sh_ image inspect -f '{{index .Config.Labels "io.buildah.stage.name"}}' localhost/e2e-stages:2)"
    second=$(sh_ image list -a -q --filter label=io.buildah.stage.name=second)
    check "the image of a stage stays" 1 "$(echo "$second" | wc -l)"
    check "...with its labels" "second" "$(sh_ image inspect -f '{{index .Config.Labels "io.buildah.stage.name"}}' "$second")"
    first=$(sh_ image list -a -q --filter label=io.buildah.stage.name=first)
    check "the image of the first stage stays" 1 "$(echo "$first" | wc -l)"
    check "a stage FROM a stage has its image as the base" "$(sh_ image inspect -f '{{.Id}}' "$first")" "$(sh_ image inspect -f '{{index .Config.Labels "io.buildah.stage.base"}}' "$second")"
    check "the first stage has its base" "$IMAGE" "$(sh_ image inspect -f '{{index .Config.Labels "io.buildah.stage.base"}}' "$first")"
    sh_ rmi -f localhost/e2e-stages:1 localhost/e2e-stages:2 "$second" "$first" > /dev/null 2>&1
}
