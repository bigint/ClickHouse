#!/usr/bin/env bash

CUR_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../shell_config.sh
. "$CUR_DIR"/../shell_config.sh

ephemeral="failed_definer_05026_${CLICKHOUSE_DATABASE}_$RANDOM"
ephemeral_definer="${ephemeral}:definer"
view="failed_definer_view_05026_$RANDOM"

${CLICKHOUSE_CLIENT} --query "CREATE USER ${ephemeral} IN memory"

if ${CLICKHOUSE_CLIENT} --query "CREATE MATERIALIZED VIEW ${view} TO ${CLICKHOUSE_DATABASE}.${view} DEFINER = ${ephemeral} SQL SECURITY DEFINER AS SELECT 1" >/dev/null 2>&1
then
    echo "UNEXPECTED SUCCESS"
    ${CLICKHOUSE_CLIENT} --query "DROP TABLE ${view}"
fi

${CLICKHOUSE_CLIENT} --query "SELECT count() FROM system.users WHERE name = '${ephemeral_definer}'"
${CLICKHOUSE_CLIENT} --query "DROP USER ${ephemeral}"
