#!/bin/bash
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


# Check OS
OS=$(cat /etc/os-release | grep ^ID= | cut -d'=' -f2)
temp="${OS%\"}"
temp="${temp#\"}"
OS="$temp"

# read from environment variables file if it exists
if [ -f ./iseclpgdb.env ]; then
    echo "Reading Database Installation variables from $(pwd)/iseclpgdb.env"
    source ./iseclpgdb.env
    env_file_exports=$(cat ./iseclpgdb.env | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
    if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
fi

DEFAULT_CERTSUBJECT="/CN=ISecl Self Sign Cert"
DEFAULT_CIPHERSUITES="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
DEFAULT_CERT_DNS="localhost"
DEFAULT_CERT_IP="127.0.0.1"
DEFAULT_DB_INSTANCE_SIZE="small"
# Variables Section. Please edit the default value as appropriate or use the iseclpgdb.env file

ISECL_PGDB_IP_INTERFACES="${ISECL_PGDB_IP_INTERFACES:-localhost}"    # network interfaces to listen for connection
ISECL_PGDB_PORT="${ISECL_PGDB_PORT:-5432}"

ISECL_PGDB_SERVICEHOST="${ISECL_PGDB_SERVICEHOST:-localhost}" # host name or ip address of service whic connects to this database
ISECL_PGDB_ALLOW_NONSSL="${ISECL_PGDB_ALLOW_NONSSL:-false}"
ISECL_PGDB_CERT_VALIDITY_DAYS="${ISECL_PGDB_CERT_VALIDITY_DAYS:-3652}"

ISECL_PGDB_CERTSUBJECT="${ISECL_PGDB_CERTSUBJECT:-$DEFAULT_CERTSUBJECT}"
ISECL_PGDB_CIPHERSUITES="${ISECL_PGDB_CIPHERSUITES:-$DEFAULT_CIPHERSUITES}"

ISECL_PGDB_CERT_DNS="${ISECL_PGDB_CERT_DNS:-$DEFAULT_CERT_DNS}"
ISECL_PGDB_CERT_IP="${ISECL_PGDB_CERT_IP:-$DEFAULT_CERT_IP}"
ISECL_PGDB_INSTANCE_SIZE="${ISECL_PGDB_INSTANCE_SIZE:-$DEFAULT_DB_INSTANCE_SIZE}"

isecl_pgdb_max_connections=""
isecl_pgdb_shared_buffers=""

# Based on the DB instance size, set max_connections and shared_buffers values
if [[ "$ISECL_PGDB_INSTANCE_SIZE" == "small" ]]; then
   isecl_pgdb_max_connections=100
   isecl_pgdb_shared_buffers=1024MB
elif [[ "$ISECL_PGDB_INSTANCE_SIZE" == "medium" ]]; then
   isecl_pgdb_max_connections=200
   isecl_pgdb_shared_buffers=2048MB
elif [[ "$ISECL_PGDB_INSTANCE_SIZE" == "large" ]]; then
   isecl_pgdb_max_connections=400
   isecl_pgdb_shared_buffers=6144MB
fi

pgdb_cert_dns=""
for dns in $(echo $ISECL_PGDB_CERT_DNS | tr "," "\n")
do
    pgdb_cert_dns=$pgdb_cert_dns"DNS:$dns,"
done
pgdb_cert_dns=${pgdb_cert_dns::-1}

pgdb_cert_ip=""
for ip in $(echo $ISECL_PGDB_CERT_IP | tr "," "\n")
do
    pgdb_cert_ip=$pgdb_cert_ip"IP:$ip,"
done
pgdb_cert_ip=${pgdb_cert_ip::-1}

echo "Installing postgres database version 11"

cd /tmp
log_file=/dev/null
if [ -z $SAVE_DB_INSTALL_LOG ] ; then
	log_file=~/isecl_pgdb_install.log
fi

# Install postgresql
if [[ "$OS" == "rhel" ]]; then
   yum install postgresql11 postgresql11-server postgresql11-contrib postgresql11-libs -y &>> $log_file
elif [[ "$OS" == "ubuntu" ]]; then   
   apt-get -y install postgresql-11 &>> $log_file
fi

if [ $? -ne 0 ] ; then
        echo "PostgreSQL-11 installation failed"
        exit 1
fi

echo "Initializing postgres database ..."

# required env variables
export PGDATA=/usr/local/pgsql/data
export PGHOST=$ISECL_PGDB_HOST
export PGPORT=$ISECL_PGDB_PORT

# make sure that we have openssl
openssl version
if [ $? != 0 ]; then
    echo "OpenSSL is not installed. Cannot create certificates needed for SSL connection to DB"
    echo "Exiting with Error.."
    exit 1
fi

# if there is no preset database folder, set it up
if [ ! -f $PGDATA/pg_hba.conf ] ; then
	# cleanup and create folders for db
	rm -Rf /usr/local/pgsql
	mkdir -p /usr/local/pgsql/data
    chown -R postgres:postgres /usr/local/pgsql

if [[ "$OS" == "rhel" ]]; then    
    sudo -u postgres /usr/pgsql-11/bin/pg_ctl initdb -D $PGDATA &>> $log_file
elif [[ "$OS" == "ubuntu" ]]; then    
    sudo -u postgres /usr/lib/postgresql/11/bin/pg_ctl initdb -D $PGDATA &>> $log_file
fi

    # make certificate and key files for TLS
    openssl req -new -x509 -days $ISECL_PGDB_CERT_VALIDITY_DAYS -newkey rsa:4096 \
        -addext "subjectAltName = $pgdb_cert_dns, $pgdb_cert_ip" \
        -nodes -text -out $PGDATA/server.crt -keyout $PGDATA/server.key -sha384 -subj "$ISECL_PGDB_CERTSUBJECT"

    chmod og-rwx $PGDATA/server.key


    # Configure the Postgres database for TLS
    mv $PGDATA/postgresql.conf $PGDATA/postgresql-original.conf
    echo "# ISECL Postgres database configuration File\n" > $PGDATA/postgresql.conf
    echo "# Original File moved to postgresql-original.conf" >> $PGDATA/postgresql.conf
    echo "# If you need further configuration changes please overwrite this file with "  >> $PGDATA/postgresql.conf
    echo "# original file and incorporate the following settings into the postgressql.conf file" >> $PGDATA/postgresql.conf

    echo "listen_addresses = '$ISECL_PGDB_IP_INTERFACES'" >> $PGDATA/postgresql.conf
    echo "port = $ISECL_PGDB_PORT" >> $PGDATA/postgresql.conf
    echo "ssl = on" >> $PGDATA/postgresql.conf
    echo "ssl_cert_file = 'server.crt'" >> $PGDATA/postgresql.conf
    echo "ssl_key_file = 'server.key'" >> $PGDATA/postgresql.conf
    echo "ssl_ciphers = '$ISECL_PGDB_CIPHERSUITES'" >> $PGDATA/postgresql.conf
    echo "max_connections = $isecl_pgdb_max_connections" >> $PGDATA/postgresql.conf
    echo "shared_buffers = $isecl_pgdb_shared_buffers" >> $PGDATA/postgresql.conf

	mv $PGDATA/pg_hba.conf $PGDATA/pg_hba-template.conf
	echo "local all postgres peer" >> $PGDATA/pg_hba.conf
	echo "local all all md5" >> $PGDATA/pg_hba.conf
    if [ $ISECL_PGDB_ALLOW_NONSSL == "true" ]; then
        if [ $ISECL_PGDB_SERVICEHOST != "localhost" ] && [ $ISECL_PGDB_SERVICEHOST != "127.0.0.1" ]; then
            echo "host all all localhost md5" >> $PGDATA/pg_hba.conf
        fi
	    echo "host all all $ISECL_PGDB_SERVICEHOST md5" >> $PGDATA/pg_hba.conf
    else 
        if [ $ISECL_PGDB_SERVICEHOST != "localhost" ] && [ $ISECL_PGDB_SERVICEHOST != "127.0.0.1" ]; then
            echo "hostssl all all localhost md5" >> $PGDATA/pg_hba.conf
        fi
        echo "# host all all $ISECL_PGDB_SERVICEHOST md5" >> $PGDATA/pg_hba.conf
        echo "hostssl all all $ISECL_PGDB_SERVICEHOST md5" >> $PGDATA/pg_hba.conf
        echo "hostnossl all all 0.0.0.0/0 reject" >> $PGDATA/pg_hba.conf
    fi

    chown -R postgres:postgres /usr/local/pgsql

fi

echo "Setting up systemctl for postgres database ..."

# setup systemd startup for postgresql
if [[ "$OS" == "rhel" ]]; then
pg_systemd=/usr/lib/systemd/system/postgresql-11.service
elif [[ "$OS" == "ubuntu" ]]; then
   if [ -f "/etc/init.d/postgresql" ]; then
           systemctl stop postgresql && systemctl disable postgresql
           rm -rf /lib/systemd/system/postgresql.service
   fi
pg_systemd=/lib/systemd/system/postgresql-11.service
fi
rm -rf $pg_systemd
echo "[Unit]" >> $pg_systemd
echo "Description=PostgreSQL database server" >> $pg_systemd
echo "Documentation=https://www.postgresql.org/docs/11/static/" >> $pg_systemd
echo "After=network.target" >> $pg_systemd
echo "After=syslog.target" >> $pg_systemd
echo "" >> $pg_systemd
echo "[Service]" >> $pg_systemd
echo "Type=forking" >> $pg_systemd
echo "User=postgres" >> $pg_systemd
echo "Group=postgres" >> $pg_systemd
echo "Environment=PGDATA=${PGDATA}" >> $pg_systemd
echo "OOMScoreAdjust=-1000" >> $pg_systemd
echo "Environment=PG_OOM_ADJUST_FILE=/proc/self/oom_score_adj" >> $pg_systemd
echo "Environment=PG_OOM_ADJUST_VALUE=0" >> $pg_systemd
if [ "$OS" == "rhel" ]
then
echo "ExecStart=/usr/pgsql-11/bin/pg_ctl start -D ${PGDATA} -l ${PGDATA}/pg_log" >> $pg_systemd
echo "ExecStop=/usr/pgsql-11/bin/pg_ctl stop -D ${PGDATA}" >> $pg_systemd
echo "ExecReload=/usr/pgsql-11/bin/pg_ctl reload -D ${PGDATA}" >> $pg_systemd
elif [ "$OS" == "ubuntu" ]
then
echo "ExecStart=/usr/lib/postgresql/11/bin/pg_ctl start -D ${PGDATA} -l ${PGDATA}/pg_log" >> $pg_systemd
echo "ExecStop=/usr/lib/postgresql/11/bin/pg_ctl stop -D ${PGDATA}" >> $pg_systemd
echo "ExecReload=/usr/lib/postgresql/11/bin/pg_ctl reload -D ${PGDATA}" >> $pg_systemd
fi
echo "" >> $pg_systemd
echo "TimeoutSec=300" >> $pg_systemd
echo "" >> $pg_systemd
echo "[Install]" >> $pg_systemd
echo "WantedBy=multi-user.target" >> $pg_systemd
echo "" >> $pg_systemd

systemctl daemon-reload &>> $log_file
systemctl enable postgresql-11.service &>> $log_file

echo "Setting up postgres database ..."

# start the database service
service postgresql-11 start &>> $log_file

sudo -E PGDATA=$PGDATA -E PGHOST=$PGHOST -E PGPORT=$PGPORT -u postgres psql postgres -c "alter system set log_connections = 'on';" &>> $log_file
sudo -E PGDATA=$PGDATA -E PGHOST=$PGHOST -E PGPORT=$PGPORT -u postgres psql postgres -c "alter system set log_disconnections = 'on';" &>> $log_file
sudo -E PGDATA=$PGDATA -E PGHOST=$PGHOST -E PGPORT=$PGPORT -u postgres psql postgres -c "CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";" &>> $log_file
