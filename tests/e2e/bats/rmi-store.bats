# SPDX-License-Identifier: Apache-2.0
# End to end tests of what the removal of an image leaves in the store: its
# layer images go with it, and a prune gives back the pages of the rows the
# removal freed.  Run it as an ordinary user for the rootless daemon, or as
# root.

load helpers
load run_lib

setup_file () {
    run_setup_file
}

teardown_file () {
    run_teardown_file
}

# layer_images: how many images of layers the store holds.
layer_images () {
    find "$XDG_DATA_HOME/velarx" -name 'layer-*.erofs' 2> /dev/null | wc -l
}

# db_bytes: the size of the database with its log.
db_bytes () {
    local total=0 f
    for f in "$XDG_DATA_HOME"/velarx/db.sqlite*; do
        [ -e "$f" ] && total=$((total + $(stat -c %s "$f")))
    done
    echo "$total"
}

@test "the removal of an image leaves its layer images out of the store, a prune shrinks the database" {
    # (an image of many files, pushed and removed: pulled again, its layer
    # is one of the registry's, with an image of its own and many rows)
    local ref=$E2E_REGISTRY/velarx-e2e/rmi-store:many small pulled ctx=$WORKDIR/many
    mkdir -p "$ctx"
    printf 'FROM %s\nRUN mkdir /many && cd /many && seq 20000 | xargs touch\n' "$IMAGE" > "$ctx/Containerfile"
    sh_ build --network none -t localhost/rmi-store:many "$ctx" > "$WORKDIR/many.log" 2>&1 || { cat "$WORKDIR/many.log"; e2e_die "build"; }
    sh_ image push --tls-verify=false --compression-format zstd:chunked localhost/rmi-store:many "$ref" > /dev/null 2>&1 || e2e_die "push"
    sh_ image rm localhost/rmi-store:many > /dev/null 2>&1 || e2e_die "rm of the built image"
    sh_ system prune -f > /dev/null 2>&1
    small=$(layer_images) before=$(db_bytes)
    sh_ image pull --tls-verify=false "$ref" > /dev/null 2>&1
    check "the image is pulled" 0 $?
    check "its layer has an image" 1 "$([ "$(layer_images)" -gt "$small" ] && echo 1)"
    pulled=$(db_bytes)
    sh_ image rm "$ref" > /dev/null 2>&1
    check "the image is removed" 0 $?
    check "rmi leaves no layer image of it in the store" "$small" "$(layer_images)"
    sh_ system prune -f > /dev/null 2>&1
    check "system prune" 0 $?
    # (at least half of what the pull added)
    check "the prune gives back the pages of its rows ($before bytes before the pull, $pulled after, $(db_bytes) now)" 1 \
          "$([ "$(db_bytes)" -lt $(((before + pulled) / 2)) ] && echo 1)"
}
