#!/usr/bin/env bash
# Tags: no-parallel

# Restoring `system.roles` replaces the global role set, so this test cannot run alongside
# another test which creates or modifies roles.

CUR_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../shell_config.sh
. "$CUR_DIR"/../shell_config.sh

role_name="role_${CLICKHOUSE_TEST_UNIQUE_NAME}"
user_name="user_${CLICKHOUSE_TEST_UNIQUE_NAME}"
table_name="table_${CLICKHOUSE_TEST_UNIQUE_NAME}"
backup_name="Disk('backups', '${CLICKHOUSE_TEST_UNIQUE_NAME}_access_restore_notifications')"

${CLICKHOUSE_CLIENT} -nm --query "
    DROP USER IF EXISTS ${user_name};
    DROP ROLE IF EXISTS ${role_name};
    DROP TABLE IF EXISTS ${CLICKHOUSE_DATABASE}.${table_name};
    CREATE TABLE ${CLICKHOUSE_DATABASE}.${table_name} (value UInt8) ENGINE = Memory;
    CREATE ROLE ${role_name};
    GRANT SELECT ON ${CLICKHOUSE_DATABASE}.${table_name} TO ${role_name};
    CREATE USER ${user_name};
    GRANT ${role_name} TO ${user_name};
"

${CLICKHOUSE_CLIENT} --query "BACKUP TABLE system.roles TO ${backup_name} FORMAT Null"

# Populate the enabled-role cache, then make its current value deny the query.
${CLICKHOUSE_CLIENT} --user="${user_name}" --query "SELECT count() FROM ${CLICKHOUSE_DATABASE}.${table_name} FORMAT Null"
${CLICKHOUSE_CLIENT} --query "REVOKE SELECT ON ${CLICKHOUSE_DATABASE}.${table_name} FROM ${role_name}"

if ${CLICKHOUSE_CLIENT} --user="${user_name}" --query "SELECT count() FROM ${CLICKHOUSE_DATABASE}.${table_name} FORMAT Null" >/dev/null 2>&1; then
    echo "access unexpectedly allowed before restore"
else
    echo "access denied before restore"
fi

${CLICKHOUSE_CLIENT} --query "RESTORE TABLE system.roles FROM ${backup_name} SETTINGS create_access='replace' FORMAT Null"

if ${CLICKHOUSE_CLIENT} --user="${user_name}" --query "SELECT count() FROM ${CLICKHOUSE_DATABASE}.${table_name} FORMAT Null" >/dev/null 2>&1; then
    echo "access allowed after restore"
else
    echo "access unexpectedly denied after restore"
fi

${CLICKHOUSE_CLIENT} -nm --query "
    DROP USER ${user_name};
    DROP ROLE ${role_name};
    DROP TABLE ${CLICKHOUSE_DATABASE}.${table_name};
"
