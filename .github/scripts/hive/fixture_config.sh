# The fixture set must match the fork variant selected for the simulator.
case "${fixture_variant}" in
    amsterdam)
        eels_fixtures="https://github.com/ethereum/execution-specs/releases/download/tests-glamsterdam-devnet@v7.2.1/fixtures_glamsterdam-devnet.tar.gz"
        eels_branch="882909a2c88751a31fa99a65176563a16c527893"
        eels_fork="Amsterdam"
        ;;
    osaka)
        eels_fixtures="https://github.com/ethereum/execution-spec-tests/releases/download/v5.3.0/fixtures_develop.tar.gz"
        eels_branch="7b8124a77280edaaad877128937b71a1e3a7ebc5"
        eels_fork="Osaka"
        ;;
    *)
        echo "unknown hive fixture variant: ${fixture_variant}"
        exit 1
        ;;
esac
