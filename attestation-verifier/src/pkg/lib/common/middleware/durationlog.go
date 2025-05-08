/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package middleware

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
	"html"

	"github.com/gorilla/mux"
)

type LogWriterMiddleware struct {
	Writer io.Writer
}

func (logWriter *LogWriterMiddleware) WriteDurationLog() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			startTime := time.Now()
			logRespWriter := newLogResponseWriter(w)
			next.ServeHTTP(logRespWriter, r)
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}

			var buffer bytes.Buffer
			var TimestampFormat = "02/Jan/2006:15:04:05"
			duration := time.Since(startTime).String()

			buffer.WriteString(host + " - [" + startTime.Format(TimestampFormat) + "] ")
			buffer.WriteString(`"` + r.Method + " " + r.RequestURI + " " + r.Proto + `" `)
			buffer.WriteString(strconv.Itoa(logRespWriter.statusCode) + " " + strconv.Itoa(logRespWriter.size) + ` "`)
			buffer.WriteString(r.UserAgent() + `" - [duration ` + duration + "]" + "\n")
			logWriter.Writer.Write(buffer.Bytes())
		})
	}
}

type logResponseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func newLogResponseWriter(w http.ResponseWriter) *logResponseWriter {
	return &logResponseWriter{ResponseWriter: w}
}

func (w *logResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *logResponseWriter) Write(body []byte) (int, error) {
	// Sanitize the user-provided value to prevent XSS
	bodyStr := string(body)
	sanitizedBodyStr := html.EscapeString(bodyStr)
	sanitizedBody := []byte(sanitizedBodyStr)

	size, err := w.ResponseWriter.Write(sanitizedBody)
	w.size += size
	return size, err
}
