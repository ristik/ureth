#!/usr/bin/env bash
# set -x

sim="${1}"
limit="${2}"
fixture_variant="${3:-}"

if [[ "${fixture_variant}" == "osaka" && "${sim}" == *"eels"* && "${limit}" == *"tests/amsterdam"* ]]; then
    echo "osaka fixtures do not support amsterdam tests"
    exit 1
fi

# Use lower parallelism for eels tests to avoid OOM-killing the runner
parallelism=16
if [[ "${sim}" == *"eels"* ]]; then
    parallelism=4
fi

build_args=()
if [[ "${BUILD_SIMULATOR:-false}" == true ]]; then
    case "${sim}" in
        ethereum/rpc-compat)
            # The next execution-apis revision switched the chain to newer Amsterdam rules.
            build_args+=(--sim.buildarg branch=377333f4de669829cebce8ab63d7466b2504f344)
            ;;
        ethereum/eels/*)
            source "$(dirname "${BASH_SOURCE[0]}")/fixture_config.sh"
            build_args+=(--sim.buildarg branch="${eels_branch}")
            if [[ "${sim}" == ethereum/eels/execute-blobs ]]; then
                build_args+=(--sim.buildarg fork="${eels_fork}")
            else
                build_args+=(--sim.buildarg fixtures="${eels_fixtures}")
            fi
            ;;
    esac
fi

cd hivetests/ || exit 1

run_hive() {
    hive \
  --sim "${sim}" \
  --sim.limit "${limit}" \
  --sim.limit.exact=false \
  --sim.parallelism "${parallelism}" \
  --client reth "${build_args[@]}" \
  2>&1 | tee /tmp/log || true
}

check_log() {
    tail -n 1 /tmp/log | sed -r 's/\x1B\[[0-9;]*[mK]//g'
}

attempt=0
max_attempts=5

while [ $attempt -lt $max_attempts ]; do
    run_hive

    # Check if no tests were run. sed removes ansi colors
    if check_log | grep -Eq '(^|[[:space:]])(suites|tests)=0([[:space:]]|$)'; then
        echo "no tests were run, retrying in 10 seconds"
        sleep 10
        attempt=$((attempt + 1))
        continue
    fi

    # Check the last line of the log for "finished", "tests failed", or "test failed"
    if check_log | grep -Eq "(finished|tests? failed)"; then
        exit 0
    else
        exit 1
    fi
done
exit 1
