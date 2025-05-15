/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"database/sql"

	"github.com/DATA-DOG/go-sqlmock"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

var mock sqlmock.Sqlmock

// NewSQLMockDataStore returns an instance of DataStore with a Mock Database connection injected into it
func NewSQLMockDataStore() (*DataStore, sqlmock.Sqlmock) {
	var db *sql.DB

	db, mock, _ = sqlmock.New()
	dialector := postgres.New(postgres.Config{
		Conn: db,
	})
	gdb, _ := gorm.Open(dialector, &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true,
		},
	})

	return &DataStore{Db: gdb}, mock
}
