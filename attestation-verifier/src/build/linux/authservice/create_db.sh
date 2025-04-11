# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

#/bin/bash

if [ "$#" -ne 3 ] ; then
    echo "The database name and user are required"
    echo "Usage :-"
    echo "      $0 database_name user_name password"
    exit 1
fi

ISECL_PGDB_DBNAME="${1:-ISECL_PGDB_DBNAME}"                # database name
ISECL_PGDB_USERNAME="${2:-ISECL_PGDB_USERNAME}"            # name of user used to connect to database
ISECL_PGDB_USERPASSWORD="${3:-$ISECL_PGDB_USERPASSWORD}"   # password for database user

echo "Creating database '${ISECL_PGDB_DBNAME}' for user '${ISECL_PGDB_USERNAME}'"

log_file="create_db_${ISECL_PGDB_DBNAME}.log"

cd /tmp
cat /dev/null > "$log_file"

su - postgres -c "psql -c \"CREATE USER ${ISECL_PGDB_USERNAME} WITH PASSWORD '${ISECL_PGDB_USERPASSWORD}';\"" &>> $log_file
su - postgres -c "psql -c \"CREATE DATABASE ${ISECL_PGDB_DBNAME};\"" &>> $log_file
su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE ${ISECL_PGDB_DBNAME} TO ${ISECL_PGDB_USERNAME};\"" &>> $log_file
su - postgres -c "psql -c \"ALTER ROLE ${ISECL_PGDB_USERNAME} NOSUPERUSER;\"" &>> $log_file
su - postgres -c "psql -c \"ALTER ROLE ${ISECL_PGDB_USERNAME} NOCREATEROLE;\"" &>> $log_file
su - postgres -c "psql -c \"ALTER ROLE ${ISECL_PGDB_USERNAME} NOCREATEDB;\"" &>> $log_file
su - postgres -c "psql -c \"ALTER ROLE ${ISECL_PGDB_USERNAME} NOREPLICATION;\"" &>> $log_file
su - postgres -c "psql -c \"ALTER ROLE ${ISECL_PGDB_USERNAME} NOBYPASSRLS;\"" &>> $log_file
su - postgres -c "psql -c \"ALTER ROLE ${ISECL_PGDB_USERNAME} NOINHERIT;\"" &>> $log_file

cd -
mv "/tmp/$log_file" .
