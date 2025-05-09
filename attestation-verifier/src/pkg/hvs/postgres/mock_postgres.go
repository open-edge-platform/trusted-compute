/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"database/sql"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jinzhu/gorm"
)

var mock sqlmock.Sqlmock

// NewSQLMockDataStore returns an instance of DataStore with a Mock Database connection injected into it
func NewSQLMockDataStore() (*DataStore, sqlmock.Sqlmock) {
	var db *sql.DB

	db, mock, _ = sqlmock.New()
	gdb, _ := gorm.Open("postgres", db)

	// enable single table setting
	gdb.SingularTable(true)

	return &DataStore{Db: gdb}, mock
}
