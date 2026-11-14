# shellcheck shell=bash
# Sourced by ci/update.sh (#167): the control host's state store, a local S3 gateway (versitygw, as
# ci/restore.sh runs it) holding only what an update pushes there: the ledger snapshot it takes before
# each switch, sealed under state.key. store_up before the first update; store_checks after pruning.
# shellcheck disable=SC2016  # checks are strings eval'd later

S3_IMAGE=${S3_IMAGE:-versity/versitygw@sha256:8319a530d08d537426e2f855bae5280709795dc73a3f0c347973ef915d6343c5}
s3name=upd-$$-s3

store_up() {
  local s3port access secret
  s3port=$(free_port)
  access=upd$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
  secret=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
  mkdir -p "$work/s3/wicket-upd"
  $DOCKER run -d --name "$s3name" --network host --user "$(id -u):$(id -g)" -v "$work/s3:/data" \
    -e ROOT_ACCESS_KEY="$access" -e ROOT_SECRET_KEY="$secret" "$S3_IMAGE" --port "127.0.0.1:$s3port" posix /data >/dev/null
  wait_for 30 "(exec 3<>/dev/tcp/127.0.0.1/$s3port) 2>/dev/null"
  printf '%s' "$secret" | w secret set s3-upd --hosts 127.0.0.1 >/dev/null
  cat >"$WICKET_HOME/state-store.yaml" <<YAML
s3:
  endpoint: http://127.0.0.1:$s3port
  bucket: wicket-upd
  prefix: upd/
  access_key_id: $access
  secret: s3-upd
YAML
  store_secret=$secret
}

store_checks() {
  local local_names store_names sb first
  log "5a. ledger snapshots in the state store (#167)"
  local_names=$(ls "$WICKET_HOME/snapshots" | sort -n | tr '\n' ' ')
  w state snapshots >"$work/snapshots.log" 2>&1 || cat "$work/snapshots.log"
  store_names=$(awk '/\.db /{print $1}' "$work/snapshots.log" | sort -n | tr '\n' ' ')
  echo "   local: $local_names"
  echo "   store: $store_names"
  check "every switch's snapshot is in the state store too, pruned alike" '[ -n "$local_names" ] && [ "$local_names" = "$store_names" ]'
  check "  sealed there: no object in the store is a SQLite database" \
    '[ -n "$(find "$work/s3/wicket-upd/upd/sealed/ledger-snapshots" -type f)" ] && ! find "$work/s3/wicket-upd" -type f -exec head -c 15 {} \; -exec echo \; | grep -q "SQLite format 3"'
  check "  the audit names its key" 'w audit --tail 2000 | grep self.snapshot | grep -q "\"store_key\":\"ledger-snapshots/"'
  # A standby with only the kit's state.key and state-store.yaml, and the store's secret: the control
  # host's files aren't needed to read one back.
  sb=$work/standby
  mkdir -p "$sb/h" "$sb/u"
  cp "$WICKET_HOME/state.key" "$WICKET_HOME/state-store.yaml" "$sb/h/"
  printf '%s' "$store_secret" | env WICKET_HOME="$sb/h" HOME="$sb/u" "$A" secret set s3-upd --hosts 127.0.0.1 >/dev/null
  first=${store_names%% *}
  env WICKET_HOME="$sb/h" HOME="$sb/u" "$A" state snapshot "$first" --out "$sb/back.db" >"$work/snapshot-get.log" 2>&1 || cat "$work/snapshot-get.log"
  check "  a standby fetches one back, as it was" 'cmp -s "$sb/back.db" "$WICKET_HOME/snapshots/$first"'
}
