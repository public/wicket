#!/bin/bash
# CLAUDE_CODE_PROCESS_WRAPPER for Remote Control: each session process runs inside a wicket box.
here="$(cd "$(dirname "$0")" && pwd)"
exec wicket wrap --manifest "$here/manifest.yaml" -- "$@"
