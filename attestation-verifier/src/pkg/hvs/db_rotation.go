/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import (
	"fmt"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	"github.com/pkg/errors"
)

var dbScriptConfig = "INSERT INTO rotate_audit_log_args (max_row_count, num_rotations) VALUES (%d, %d);"

var dbScript = `
DROP TABLE IF EXISTS rotate_audit_log_args;
CREATE TABLE IF NOT EXISTS rotate_audit_log_args (
    max_row_count integer,
    num_rotations integer
);
-- Create trigger function and trigger
CREATE OR REPLACE FUNCTION insert_audit_log_partition()
RETURNS trigger AS $func$
DECLARE
    max_row_cnt integer;
    count_in_primary_partition integer;
BEGIN
    IF NOT EXISTS (SELECT relname FROM pg_class WHERE relname='audit_log_entry_0') THEN
        EXECUTE 'CREATE TABLE audit_log_entry_0 (check(0=0)) INHERITS (audit_log_entry);';
    END IF;

    SELECT max_row_count INTO max_row_cnt FROM rotate_audit_log_args LIMIT 1;
    SELECT n_live_tup INTO count_in_primary_partition FROM pg_stat_all_tables WHERE relname = 'audit_log_entry_0';
    IF count_in_primary_partition >= max_row_cnt THEN
        PERFORM public.rotate_audit_log_partitions();
    END IF;

    INSERT INTO audit_log_entry_0 Values (NEW.*);
    NEW.id = '11111111-1111-1111-1111-111111111111';
    RETURN NEW;
END;
$func$
LANGUAGE plpgsql VOLATILE;

CREATE OR REPLACE FUNCTION cleanup_audit_log()
RETURNS trigger AS $func$
BEGIN
    DELETE FROM audit_log_entry WHERE id = '11111111-1111-1111-1111-111111111111';
    RETURN NULL;
END;
$func$
LANGUAGE plpgsql VOLATILE;

DROP TRIGGER IF EXISTS insert_audit_log_trigger ON audit_log_entry;

CREATE TRIGGER insert_audit_log_trigger
BEFORE INSERT ON audit_log_entry
FOR EACH ROW EXECUTE PROCEDURE insert_audit_log_partition();

DROP TRIGGER IF EXISTS cleanup_audit_log_trigger ON audit_log_entry;

CREATE TRIGGER cleanup_audit_log_trigger
AFTER INSERT ON audit_log_entry
FOR EACH ROW EXECUTE PROCEDURE cleanup_audit_log();

-- Rotation function
CREATE OR REPLACE FUNCTION public.rotate_audit_log_partitions()
RETURNS integer AS $func$

DECLARE
    max_row_cnt integer;
    r_num integer;
    count_in_primary_partition integer;
    counter INTEGER := r_num;

BEGIN
    -- Acquire a lock to make sure that there are no concurrent rotation calls
    LOCK TABLE audit_log_entry_0 IN ACCESS EXCLUSIVE MODE;

    SELECT max_row_count, num_rotations INTO max_row_cnt, r_num FROM rotate_audit_log_args LIMIT 1;

    SELECT COUNT (*) INTO count_in_primary_partition FROM audit_log_entry_0;
    IF count_in_primary_partition >= max_row_cnt THEN
        -- Rotate audit log table
        DECLARE
            table_name_row RECORD;
            table_name varchar(25);
            table_num INT;
        BEGIN
            -- looping through each partition table
            FOR table_name_row IN
                -- select audit log partitions
                SELECT tablename FROM pg_catalog.pg_tables WHERE tablename LIKE 'audit_log_entry_%' ORDER BY tablename DESC
            LOOP
                table_name := table_name_row.tablename;
                table_num := RIGHT(table_name, 1);

                IF table_num >= r_num-1 THEN
                -- if partition number greater than number rotations, drop the table
                    EXECUTE 'DROP TABLE ' || table_name;
                ELSE
                BEGIN
                -- rotate the table
                    RAISE NOTICE 'Table Name: %', table_name;
                    EXECUTE 'ALTER TABLE audit_log_entry_' || table_num || ' RENAME TO audit_log_entry_' || table_num+1;
                    EXCEPTION WHEN OTHERS THEN
                        RAISE NOTICE '% %', SQLERRM, SQLSTATE;
                    CONTINUE;
                END;
                END IF;
            END LOOP;
        END;
        IF NOT EXISTS(SELECT relname FROM pg_class WHERE relname='audit_log_entry_0') THEN
            EXECUTE 'CREATE TABLE audit_log_entry_0 (check(0=0)) INHERITS (audit_log_entry);';
        END IF;
    END IF;
    RETURN 0;
END
$func$
LANGUAGE plpgsql VOLATILE;
`

func (a *App) configDBRotation() error {
	c := a.configuration()
	if c == nil {
		return errors.New("Failed to load configuration file")
	}
	dataStore, err := postgres.NewDataStore(postgres.NewDatabaseConfig(constants.DBTypePostgres, &c.DB))
	if err != nil {
		return errors.Wrap(err, "Failed to connect database")
	}
	if err := dataStore.ExecuteSql(&dbScript); err != nil {
		return errors.Wrap(err, "failed to configure trigger in database")
	}
	sqlConfigCmd := fmt.Sprintf(dbScriptConfig, c.AuditLog.MaxRowCount, c.AuditLog.NumRotated)
	return errors.Wrap(dataStore.ExecuteSql(&sqlConfigCmd), "failed to configure rotation parameters in database")
}
