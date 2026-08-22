#!/usr/bin/env bash
# Tags: no-parallel

# `RESTORE TABLE system.roles` operates on the global access-entity set, so this
# test must not restore roles created by another test concurrently.

CUR_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../shell_config.sh
. "$CUR_DIR"/../shell_config.sh

victim="restore_dependent_victim_${CLICKHOUSE_TEST_UNIQUE_NAME}"
role="restore_dependent_role_${CLICKHOUSE_TEST_UNIQUE_NAME}"
restorer="restore_dependent_restorer_${CLICKHOUSE_TEST_UNIQUE_NAME}"
backup_name="Disk('backups', '${CLICKHOUSE_TEST_UNIQUE_NAME}')"

${CLICKHOUSE_CLIENT} -m --query "
DROP USER IF EXISTS ${restorer};
DROP USER IF EXISTS ${victim};
DROP ROLE IF EXISTS ${role};
CREATE USER ${victim};
CREATE ROLE ${role};
GRANT ${role} TO ${victim};
"

${CLICKHOUSE_CLIENT} --query "BACKUP TABLE system.roles TO ${backup_name} FORMAT Null"
${CLICKHOUSE_CLIENT} --query "DROP ROLE ${role}"

${CLICKHOUSE_CLIENT} -m --query "
CREATE USER ${restorer};
GRANT CREATE ROLE ON *.* TO ${restorer};
"

# Restoring the role would also restore its grant to the existing victim.
# Creating roles alone must not authorize that dependent user update.
${CLICKHOUSE_CLIENT} --user="${restorer}" --query \
    "RESTORE TABLE system.roles FROM ${backup_name} FORMAT Null" 2>&1 | grep -om1 "ACCESS_DENIED"

# Altering the dependent user is necessary but does not authorize granting the role.
${CLICKHOUSE_CLIENT} --query "GRANT ALTER USER ON * TO ${restorer}"
${CLICKHOUSE_CLIENT} --user="${restorer}" --query \
    "RESTORE TABLE system.roles FROM ${backup_name} FORMAT Null" 2>&1 | grep -om1 "ACCESS_DENIED"

${CLICKHOUSE_CLIENT} --query "GRANT ROLE ADMIN ON *.* TO ${restorer}"
${CLICKHOUSE_CLIENT} --user="${restorer}" --query \
    "RESTORE TABLE system.roles FROM ${backup_name} FORMAT Null"

${CLICKHOUSE_CLIENT} --query "
SELECT count()
FROM system.role_grants
WHERE user_name = '${victim}' AND granted_role_name = '${role}'
"

${CLICKHOUSE_CLIENT} -m --query "
DROP USER IF EXISTS ${restorer};
DROP USER IF EXISTS ${victim};
DROP ROLE IF EXISTS ${role};
"
