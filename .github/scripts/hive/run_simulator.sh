#!/usr/bin/env bash
set -uo pipefail

sim=$1
limit=$2
fixture_variant=${3:-osaka}
cases=${4:-}
suite=${5:-}
profile=${6:-compatibility}
scripts="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
results="${HIVE_RESULTS_ROOT:-$PWD/hive-results}"
mkdir -p "$results" || exit 1
results="$(cd "$results" && pwd)"

selection=()
if [[ -n "$cases" ]]; then
    selection=(--cases "$scripts/$cases")
    if [[ -n "$suite" ]]; then
        selection+=(--suite "$suite")
    fi
    limit=$(python3 "$scripts/validate_attempt.py" --pattern "${selection[@]}") || exit 1
fi

parallelism=16
build_args=()
case "$sim" in
    ethereum/rpc-compat)
        # The next execution-apis revision switched the chain to newer Amsterdam rules.
        build_args+=(--sim.buildarg branch=377333f4de669829cebce8ab63d7466b2504f344)
        ;;
    ethereum/eels/*)
        parallelism=4
        source "$scripts/fixture_config.sh"
        build_args+=(--sim.buildarg branch="$eels_branch")
        if [[ "$sim" == ethereum/eels/execute-blobs ]]; then
            build_args+=(--sim.buildarg fork="$eels_fork")
        else
            build_args+=(--sim.buildarg fixtures="$eels_fixtures")
        fi
        # Select the pinned source build and load a completion check in the
        # pytest process. The default Dockerfile's legacy base tag floats.
        target="hivetests/simulators/$sim"
        cp "$target/Dockerfile.git" "$target/Dockerfile" || exit 1
        cp "$scripts/pytest_hive_completion.py" "$target/" || exit 1
        cat >> "$target/Dockerfile" <<'DOCKER'

COPY pytest_hive_completion.py /opt/reth-hive/
ENV PYTHONPATH=/opt/reth-hive PYTEST_PLUGINS=pytest_hive_completion
DOCKER
        ;;
esac

cd hivetests || exit 1
for ((attempt = 1; attempt <= 5; attempt++)); do
    attempt_dir=$(mktemp -d "$results/attempt-$attempt.XXXXXXXX") || exit 1
    echo "Hive attempt $attempt: $sim / $limit"
    hive --sim "^$sim$" --sim.limit "$limit" --sim.parallelism "$parallelism" \
        --client reth --results-root "$attempt_dir" "${build_args[@]}" 2>&1 | tee "$attempt_dir/hive.log"
    pipeline_status=("${PIPESTATUS[@]}")
    if ((pipeline_status[1] != 0)); then
        exit 1
    fi
    if ! python3 "$scripts/validate_attempt.py" --results "$attempt_dir" --simulator "$sim" \
        --hive-exit "${pipeline_status[0]}" "${selection[@]}"; then
        if ((attempt < 5)); then
            sleep 10
        fi
        continue
    fi

    failures="$scripts/expected_failures.yaml"
    ignored="$scripts/ignored_tests.yaml"
    if [[ "$profile" == gate ]]; then
        failures="$scripts/cancun_expected_failures.yaml"
        ignored=/dev/null
    fi
    status=0
    for report in "$attempt_dir"/[0-9]*-*.json; do
        python3 "$scripts/parse.py" "$report" --exclusion "$failures" --ignored "$ignored" \
            --fixture-variant "$fixture_variant" || status=1
    done
    exit "$status"
done
exit 1
