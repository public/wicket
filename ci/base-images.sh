# Sourced by ci/install-test.sh and ci/install-acceptance.sh: the distribution images they install
# into, pinned by digest (#720). A tag can be pushed again, a digest can't; the tag before the digest
# says which release it is, and Docker uses only the digest. Renovate proposes new digests.

# pinned_base NAME: NAME (ubuntu:24.04 or debian:12) as a reference pinned by digest. A reference
# that already has a digest is kept as given; anything else is refused.
pinned_base() {
    case $1 in
    ubuntu:24.04) echo "ubuntu:24.04@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289" ;;
    debian:12) echo "debian:12@sha256:268fb24c39bca92d326dd83ea3abebe4a3f7751c804ffef23bb6d857dd343ff8" ;;
    *@sha256:*) echo "$1" ;;
    *)
        echo "$1: not a pinned base image (ubuntu:24.04, debian:12, or a reference with @sha256:)" >&2
        return 1
        ;;
    esac
}
