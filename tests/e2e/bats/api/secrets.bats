# SPDX-License-Identifier: Apache-2.0
# Secrets through the podman API and the CLI.

load ../helpers
load ../api_helpers

setup_file () { api_setup_file; }

teardown_file () { api_teardown_file; }

setup () { api_setup; }

@test "secret create, list, inspect and exists" {
    printf 'hunter2' | pm secret create --label k=v apisec - > /dev/null
    check "secret create" 0 $?
    out=$(pm secret ls --format '{{.Name}}')
    check "secret ls" "apisec" "$out"
    out=$(pm secret inspect --showsecret --format '{{.SecretData}} {{.Spec.Labels}}' apisec)
    check "secret inspect" "hunter2 map[k:v]" "$out"
    out=$(pm secret inspect --format '{{.SecretData}}' apisec)
    check "secret inspect without the data" "" "$out"
    pm secret exists apisec
    check "secret exists" 0 $?
    printf 'x' | pm secret create apisec - > /dev/null 2>&1
    check "secret create of an existing secret" 125 $?
    out=$(printf 'x' | api -o /dev/null -w '%{http_code}' -X POST --data-binary @- 'http://d/v5.0.0/libpod/secrets/create?name=apisec')
    check "secret create conflict" 409 "$out"
    out=$(api -o /dev/null -w '%{http_code}' -X POST --data-binary 'x' 'http://d/v5.0.0/libpod/secrets/create?name=a%2Fb')
    check "secret create with an invalid name" 400 "$out"
    out=$(api -o /dev/null -w '%{http_code}' -X POST --data-binary '' 'http://d/v5.0.0/libpod/secrets/create?name=empty')
    check "secret create without data" 400 "$out"
}

@test "secret data files" {
    out=$(ls "$XDG_DATA_HOME"/velarx/secrets | wc -l)
    check "secret data files" 1 "$out"
    check "secret data mode" "600" "$(stat -c %a "$XDG_DATA_HOME"/velarx/secrets/*)"
}

@test "secrets in a container and removal of a secret in use" {
    out=$(pm run --rm --secret apisec --secret apisec,type=env,target=PW "$IMG" sh -c 'cat /run/secrets/apisec; echo " $PW"')
    check "run with secrets" "hunter2 hunter2" "$out"
    pm create --name secuser --secret apisec "$IMG" true > /dev/null
    pm secret rm apisec > /dev/null 2>&1
    check "secret rm of a secret in use" 125 $?
    pm rm secuser > /dev/null
}

@test "secret rm" {
    pm secret rm apisec > /dev/null
    check "secret rm" 0 $?
    pm secret exists apisec
    check "secret rm removes" 1 $?
    check "secret rm removes the data" 0 "$(ls "$XDG_DATA_HOME"/velarx/secrets | wc -l)"
}

@test "compat secrets" {
    out=$(api -X POST -H 'Content-Type: application/json' \
              -d "{\"Name\":\"dksec\",\"Data\":\"$(printf hello | base64)\"}" http://d/v1.41/secrets/create | jq -r .ID)
    check_match "compat secret create" "^[0-9a-f]{25}$" "$out"
    out=$(api http://d/v1.41/secrets | jq -r '.[0].Spec.Name')
    check "compat secret list" "dksec" "$out"
    out=$(api http://d/v1.41/secrets/dksec | jq -r '.Spec.Name + " " + (.Version.Index | tostring)')
    check "compat secret inspect" "dksec 1" "$out"
    out=$(api -o /dev/null -w '%{http_code}' -X DELETE http://d/v1.41/secrets/dksec)
    check "compat secret remove" 204 "$out"
    out=$(api -o /dev/null -w '%{http_code}' -X DELETE http://d/v1.41/secrets/dksec)
    check "compat secret remove of a missing secret" 404 "$out"
}

@test "secret rm all" {
    printf 'a' | pm secret create all1 - > /dev/null
    printf 'b' | pm secret create all2 - > /dev/null
    out=$(api -o /dev/null -w '%{http_code}' -X DELETE 'http://d/v5.0.0/libpod/secrets/all1?all=true')
    check "secret rm all" 204 "$out"
    check "secret rm all removed them" 0 "$(pm secret ls -q | wc -l)"
}
