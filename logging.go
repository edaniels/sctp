// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"fmt"

	"github.com/pion/logging"
)

// TODO(erd): need to undo these cause of bad scope. or make new option
type leveledLoggerWithName struct {
	logger  logging.LeveledLogger
	name    string
	nameMsg string
}

func newLeveledLoggerWithName(logger logging.LeveledLogger, name string) leveledLoggerWithName {
	return leveledLoggerWithName{logger: logger, name: name, nameMsg: fmt.Sprintf("[%s] ", name)}
}

func (l leveledLoggerWithName) withName(name string) leveledLoggerWithName {
	return newLeveledLoggerWithName(l.logger, fmt.Sprintf("%s:%s", l.name, name))
}

func (l leveledLoggerWithName) Trace(msg string) {
	l.logger.Trace(l.nameMsg + msg)
}

func (l leveledLoggerWithName) Tracef(format string, args ...interface{}) {
	l.logger.Tracef(l.nameMsg+format, args...)
}

func (l leveledLoggerWithName) Debug(msg string) {
	l.logger.Debug(l.nameMsg + msg)
}

func (l leveledLoggerWithName) Debugf(format string, args ...interface{}) {
	l.logger.Debugf(l.nameMsg+format, args...)
}

func (l leveledLoggerWithName) Info(msg string) {
	l.logger.Info(l.nameMsg + msg)
}

func (l leveledLoggerWithName) Infof(format string, args ...interface{}) {
	l.logger.Infof(l.nameMsg+format, args...)
}

func (l leveledLoggerWithName) Warn(msg string) {
	l.logger.Warn(l.nameMsg + msg)
}

func (l leveledLoggerWithName) Warnf(format string, args ...interface{}) {
	l.logger.Warnf(l.nameMsg+format, args...)
}

func (l leveledLoggerWithName) Error(msg string) {
	l.logger.Error(l.nameMsg + msg)
}

func (l leveledLoggerWithName) Errorf(format string, args ...interface{}) {
	l.logger.Errorf(l.nameMsg+format, args...)
}
