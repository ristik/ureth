# The fixture set must match the fork variant selected for the simulator.
case "${fixture_variant}" in
    amsterdam)
        eels_fixtures="https://github.com/ethereum/execution-specs/releases/download/tests-glamsterdam-devnet@v7.2.1/fixtures_glamsterdam-devnet.tar.gz"
        eels_branch="devnets/glamsterdam/7"
        eels_fork="Amsterdam"
        ;;
    osaka)
        eels_fixtures="https://github.com/ethereum/execution-spec-tests/releases/download/v5.3.0/fixtures_develop.tar.gz"
        eels_branch="mainnet"
        eels_fork="Osaka"
        ;;
    *)
        echo "unknown hive fixture variant: ${fixture_variant}"
        exit 1
        ;;
esac
