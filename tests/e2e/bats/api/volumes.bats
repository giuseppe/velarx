# SPDX-License-Identifier: Apache-2.0
# Volumes through the podman API and the CLI.

load ../helpers
load ../api_helpers

setup_file () { api_setup_file; }

teardown_file () { api_teardown_file; }

setup () { api_setup; }

@test "volume create, inspect and ls" {
    pm volume create --label x=y apivol > /dev/null
    check "volume create" 0 $?
    out=$(pm volume inspect apivol --format '{{.Name}} {{.Labels}}')
    check "volume inspect" "apivol map[x:y]" "$out"
    out=$(pm volume ls --format '{{.Name}}')
    check "volume ls" "apivol" "$out"
}

@test "volume ls name filter is a regular expression" {
    # podman's: the name filter is a regular expression
    pm volume create apivol_2x > /dev/null
    check "volume ls --filter name=REGEX" "apivol_2x" "$(pm volume ls --filter 'name=l_2.+' --format '{{.Name}}')"
    pm volume rm apivol_2x > /dev/null
}

@test "volume rm of a missing volume, bind volume of a missing directory, create conflicts" {
    check "volume rm of a missing volume" 'Error: no volume with name "nosuchvol" found: no such volume' \
        "$(pm volume rm nosuchvol 2>&1)"
    check "a bind volume of a missing directory" \
        "Error: invalid volume option device for driver 'local': faccessat /nonexistent-velarx: no such file or directory" \
        "$(pm volume create -o type=bind -o device=/nonexistent-velarx bindvol 2>&1)"
    out=$(pm volume create apivol 2>&1 > /dev/null; echo $?)
    check_match "volume create of an existing volume" "exists|1$" "$out"
    out=$(api -o /dev/null -w '%{http_code}' -X POST -d '{"Name":"apivol"}' http://d/v5.0.0/libpod/volumes/create)
    # podman: a NewVolume that fails is a 500
    check "volume create conflict" 500 "$out"
    out=$(api -X POST -d '{"Name":"apivol","IgnoreIfExists":true}' http://d/v5.0.0/libpod/volumes/create | jq -r .Name)
    check "volume create ignoring existing" "apivol" "$out"
}

@test "compat volume list and inspect" {
    out=$(api http://d/v1.41/volumes | jq -r '.Volumes[0].Name + " " + (.Warnings | length | tostring)')
    check "compat volume list" "apivol 0" "$out"
    out=$(api http://d/v1.41/volumes/apivol | jq -r '.Name + " " + .Driver + " " + .Scope')
    check "compat volume inspect" "apivol local local" "$out"
}

@test "volume label filter, exists" {
    out=$(pm volume ls --filter label=x=y --format '{{.Name}}')
    check "volume label filter" "apivol" "$out"
    out=$(pm volume ls --filter label=x=z --format '{{.Name}}')
    check "volume label filter without a match" "" "$out"
    pm volume exists apivol
    check "volume exists" 0 $?
    pm volume exists nope
    check "volume exists of a missing volume" 1 $?
    out=$(api -o /dev/null -w '%{http_code}' http://d/v5.0.0/libpod/volumes/nope/json)
    check "volume inspect of a missing volume" 404 "$out"
}

@test "volume content and rm" {
    pm run --rm -v apivol:/data "$IMG" sh -c 'echo kept > /data/f' > /dev/null
    out=$(pm run --rm -v apivol:/data "$IMG" cat /data/f)
    check "volume content" "kept" "$out"
    pm volume rm apivol > /dev/null
    check "volume rm" 0 $?
    pm volume exists apivol
    check "volume rm removes" 1 $?
    pm volume rm apivol > /dev/null 2>&1
    check "volume rm missing" 1 $?
}

@test "volume export and import" {
    # export and import of the data, which is put there by the daemon's
    # files: the checks do not need a container
    pm volume create expvol > /dev/null
    mp=$(pm volume inspect expvol --format '{{.Mountpoint}}')
    mkdir "$mp/sub" && echo exported > "$mp/sub/f" && ln -s sub/f "$mp/link"
    api -o "$WORKDIR/vol.tar" http://d/v5.0.0/libpod/volumes/expvol/export
    check "volume export" "link sub/ sub/f " "$(tar -tf "$WORKDIR/vol.tar" | sort | tr '\n' ' ')"
    pm volume create impvol > /dev/null
    out=$(api -o /dev/null -w '%{http_code}' -X POST --data-binary @"$WORKDIR/vol.tar" \
              -H 'Content-Type: application/x-tar' http://d/v5.0.0/libpod/volumes/impvol/import)
    check "volume import" 204 "$out"
    mp2=$(pm volume inspect impvol --format '{{.Mountpoint}}')
    check "volume import content" "exported sub/f" "$(cat "$mp2/link") $(readlink "$mp2/link")"
    # a tar that writes through a link it carries is refused
    mkdir "$WORKDIR/evil" && ln -s "$WORKDIR/outside" "$WORKDIR/evil/esc" && mkdir -p "$WORKDIR/outside"
    mkdir "$WORKDIR/evil2" && echo pwn > "$WORKDIR/evil2/pwned"
    (cd "$WORKDIR" && tar -cf evil.tar -C evil esc && tar -rf evil.tar --transform 's,^,esc/,' -C evil2 pwned)
    out=$(api -o /dev/null -w '%{http_code}' -X POST --data-binary @"$WORKDIR/evil.tar" \
              http://d/v5.0.0/libpod/volumes/impvol/import)
    check "volume import refuses a link to the outside" 400 "$out"
    check "volume import wrote nothing outside" "0" "$(ls "$WORKDIR/outside" | wc -l)"
    out=$(api -o /dev/null -w '%{http_code}' http://d/v5.0.0/libpod/volumes/nope/export)
    check "volume export of a missing volume" 404 "$out"
}

@test "volume prune" {
    pm volume prune -f > /dev/null
    check "volume prune" 0 $?
    out=$(pm volume ls -q | wc -l)
    check "volume prune removes the unused volumes" 0 "$out"
    pm volume create prunevol > /dev/null
    out=$(api -X POST http://d/v1.41/volumes/prune | jq -r '.VolumesDeleted[0]')
    check "compat volume prune" "prunevol" "$out"
    # the bytes the volumes had are reported, by both APIs (libpod's per
    # volume, Docker's in all)
    pm volume create sizedvol > /dev/null
    head -c 1048576 /dev/zero > "$(pm volume inspect sizedvol --format '{{.Mountpoint}}')/f"
    out=$(api -X POST "http://d/v5.0.0/libpod/volumes/prune?dryrun=true" | jq -r '.[0].Id + " " + (.[0].Size >= 1048576 | tostring)')
    check "a dry run of the libpod prune says what the volume has" "sizedvol true" "$out"
    out=$(api -X POST http://d/v1.41/volumes/prune | jq -r '.VolumesDeleted[0] + " " + (.SpaceReclaimed >= 1048576 | tostring)')
    check "the compat volume prune reclaims what the volume had" "sizedvol true" "$out"
}

@test "volume rm of a volume in use" {
    id=$(pm create --pull never -v usedvol:/d "$IMG" true)
    check "volume rm of a volume in use" \
        "Error: volume usedvol is being used by the following container(s): $id: volume is being used" \
        "$(pm volume rm usedvol 2>&1)"
    # podman's -t -1 (no limit) as the Go uint it sends
    pm volume rm -t -1 -f usedvol > /dev/null
    check "volume rm -f -t -1" 0 $?
    pm rm -t 0 -f "$id" > /dev/null 2>&1
    if selinuxenabled 2> /dev/null; then
        # the volume made for a container takes its file type
        id=$(pm create --pull never --security-opt label=filetype:usr_t -v ftvol:/d "$IMG" true)
        mp=$(pm volume inspect ftvol --format '{{.Mountpoint}}')
        check "a new volume takes the file type of its container" usr_t \
            "$(stat -c %C "$mp" | cut -d: -f3)"
        pm rm -t 0 -f "$id" > /dev/null 2>&1
        pm volume rm ftvol > /dev/null 2>&1
    fi
}

@test "volume rename of a volume a container uses" {
    id=$(pm create --pull never -v rnvol:/d "$IMG" true)
    out=$(api -w '\n%{http_code}' -X POST "http://d/v5.0.0/libpod/volumes/rnvol/rename?newName=rnvol2")
    check "rename of a volume in use" 409 "$(tail -n1 <<< "$out")"
    check "the refusal names the container" 1 "$(grep -c "$id" <<< "$out")"
    pm volume inspect rnvol > /dev/null
    check "the volume is still there" 0 $?
    pm rm -t 0 -f "$id" > /dev/null 2>&1
    out=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/volumes/rnvol/rename?newName=rnvol2")
    check "rename once the container is gone" 204 "$out"
    pm volume rm rnvol2 > /dev/null
}

@test "a volume directory holds volume.json, which moves with a rename" {
    pm volume create --label k=v dirvol > /dev/null
    mp=$(pm volume inspect dirvol --format '{{.Mountpoint}}')
    dir=$(dirname "$mp")
    check "volume.json has the labels" v "$(jq -r .labels.k "$dir/volume.json")"
    check "volume.json is private" 600 "$(stat -c %a "$dir/volume.json")"
    echo x > "$mp/f"
    out=$(api -o /dev/null -w '%{http_code}' -X POST "http://d/v5.0.0/libpod/volumes/dirvol/rename?newName=dirvol2")
    check "volume rename" 204 "$out"
    new=$(pm volume inspect dirvol2 --format '{{.Mountpoint}}')
    check "the data moved with the volume" x "$(cat "$new/f")"
    check "the file moved with the volume" v "$(jq -r .labels.k "$(dirname "$new")/volume.json")"
    check "the old directory is gone" no "$([ -e "$dir" ] && echo yes || echo no)"
    check "no volume is left half built" 0 "$(ls -A "$(dirname "$dir")" | grep -c '^\.new-')"
    check "the volume is listed under its new name" dirvol2 "$(pm volume ls --filter label=k=v --format '{{.Name}}')"
    pm volume rm dirvol2 > /dev/null
    check "the directory goes with the volume" no "$([ -e "$(dirname "$new")" ] && echo yes || echo no)"
}
