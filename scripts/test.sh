#!/usr/bin/env bash
# Runs formatting check, Release build and all tests.
#   Unit tests only:            scripts/test.sh unit
#   Everything (needs infra):   AUTHAPI_TEST_SQL='Server=localhost,1433;User Id=sa;Password=...;TrustServerCertificate=true' \
#                               AUTHAPI_TEST_REDIS=localhost:6379 scripts/test.sh all
set -euo pipefail
cd "$(dirname "$0")/.."
mode="${1:-all}"

dotnet restore AuthenticationAPI.sln
dotnet format AuthenticationAPI.sln --verify-no-changes --no-restore
dotnet build AuthenticationAPI.sln -c Release --no-restore

if [[ "$mode" == "unit" ]]; then
  dotnet test AuthenticationAPI.sln -c Release --no-build --filter "Category=Unit" --logger "trx;LogFileName=unit.trx" --results-directory TestResults
else
  : "${AUTHAPI_TEST_SQL:?AUTHAPI_TEST_SQL must be set for the full run (integration tests would otherwise be SKIPPED)}"
  dotnet test AuthenticationAPI.sln -c Release --no-build --logger "trx;LogFileName=all.trx" --results-directory TestResults
fi
