// Copyright 2026, Radetski
// SPDX-License-Identifier: GPL-3.0

// Package xraylog installs the lightweight console log handler Xray writes through.
package xraylog

import (
	"log"
	"os"
	"sync"

	coreapplog "github.com/xtls/xray-core/app/log"
	corecommlog "github.com/xtls/xray-core/common/log"
)

// consoleLogWriter implements a lightweight log writer without redundant timestamps,
// as the Android Logcat system already timestamps all log entries.
type consoleLogWriter struct {
	logger *log.Logger
}

func (w *consoleLogWriter) Write(s string) error {
	w.logger.Print(s)
	return nil
}

func (w *consoleLogWriter) Close() error {
	return nil
}

func createStdoutLogWriter() corecommlog.WriterCreator {
	return func() corecommlog.Writer {
		return &consoleLogWriter{
			logger: log.New(os.Stdout, "", 0),
		}
	}
}

var registerConsoleLogHandlerOnce sync.Once

// RegisterConsoleHandler registers the console writer with Xray. Xray keeps a single global
// registry, so the writer is registered exactly once per process however often this is called.
func RegisterConsoleHandler() {
	registerConsoleLogHandlerOnce.Do(func() {
		_ = coreapplog.RegisterHandlerCreator(
			coreapplog.LogType_Console,
			func(lt coreapplog.LogType, options coreapplog.HandlerCreatorOptions) (corecommlog.Handler, error) {
				return corecommlog.NewLogger(createStdoutLogWriter()), nil
			},
		)
	})
}
