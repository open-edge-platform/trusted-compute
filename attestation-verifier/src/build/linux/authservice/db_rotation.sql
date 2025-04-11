CREATE TABLE rotate_reports_args (
    max_row_count integer,
    num_rotations integer
);
-- INSERT INTO rotate_reports_args (max_row_count, num_rotations) VALUES (10, 5);

-- Create trigger function and trigger
CREATE OR REPLACE FUNCTION insert_report_partition()
RETURNS trigger AS $func$
DECLARE
    max_row_cnt integer;
    count_in_primary_partition integer;
BEGIN
    IF NOT EXISTS (SELECT relname FROM pg_class WHERE relname='reports_entry_0') THEN
        EXECUTE 'CREATE TABLE reports_entry_0 (check(0=0)) INHERITS (reports);';
    END IF;

    SELECT max_row_count INTO max_row_cnt FROM rotate_reports_args LIMIT 1;
    SELECT n_live_tup INTO count_in_primary_partition FROM pg_stat_all_tables WHERE relname = 'reports_entry_0';
    IF count_in_primary_partition >= max_row_cnt THEN
        PERFORM public.rotate_reports_partitions();
    END IF;

    INSERT INTO reports_entry_0 Values (NEW.*);
    NEW.id = '11111111-1111-1111-1111-111111111111';
    RETURN NEW;
END;
$func$
LANGUAGE plpgsql VOLATILE;

CREATE OR REPLACE FUNCTION cleanup_reports()
RETURNS trigger AS $func$
BEGIN
    DELETE FROM reports WHERE id = '11111111-1111-1111-1111-111111111111';
    RETURN NULL;
END;
$func$
LANGUAGE plpgsql VOLATILE;

CREATE TRIGGER insert_report_trigger
BEFORE INSERT ON reports
FOR EACH ROW EXECUTE PROCEDURE insert_report_partition();

CREATE TRIGGER cleanup_report_trigger
AFTER INSERT ON reports
FOR EACH ROW EXECUTE PROCEDURE cleanup_reports();

-- Rotation function
CREATE OR REPLACE FUNCTION public.rotate_reports_partitions()
RETURNS integer AS $func$

DECLARE
    max_row_cnt integer;
    r_num integer;
    count_in_primary_partition integer;
    counter INTEGER := r_num;

BEGIN
    -- Acquire a lock to make sure that there are no concurrent rotation calls
    LOCK TABLE reports_entry_0 IN ACCESS EXCLUSIVE MODE;

    SELECT max_row_count, num_rotations INTO max_row_cnt, r_num FROM rotate_reports_args LIMIT 1;

    SELECT COUNT (*) INTO count_in_primary_partition FROM reports_entry_0;
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
                SELECT tablename FROM pg_catalog.pg_tables WHERE tablename LIKE 'reports_entry_%' ORDER BY tablename DESC
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
                    EXECUTE 'ALTER TABLE reports_entry_' || table_num || ' RENAME TO reports_entry_' || table_num+1;
                    EXCEPTION WHEN OTHERS THEN
                        RAISE NOTICE '% %', SQLERRM, SQLSTATE;
                    CONTINUE;
                END;
                END IF;
            END LOOP;
        END;
        IF NOT EXISTS(SELECT relname FROM pg_class WHERE relname='reports_entry_0') THEN
            EXECUTE 'CREATE TABLE reports_entry_0 (check(0=0)) INHERITS (reports);';
        END IF;
    END IF;
    RETURN 0;
END
$func$
LANGUAGE plpgsql VOLATILE;

