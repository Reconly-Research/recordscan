package logging

import (
	"fmt"
	"log"
	"os"
	"time"
)

type Logger struct {
	verbose bool
	quiet   bool
	base    *log.Logger
}

func New(verbose, quiet bool) *Logger {
	return &Logger{
		verbose: verbose,
		quiet:   quiet,
		base:    log.New(os.Stdout, "", 0),
	}
}

func (l *Logger) Info(msg string, args ...any) {
	if l.quiet {
		return
	}
	l.print("INFO", "\033[34m", msg, args...)
}

func (l *Logger) Debug(msg string, args ...any) {
	if l.quiet || !l.verbose {
		return
	}
	l.print("DEBUG", "\033[90m", msg, args...)
}

func (l *Logger) Error(msg string, args ...any) {
	l.print("ERROR", "\033[31m", msg, args...)
}

func (l *Logger) print(level, color, msg string, args ...any) {
	const (
		clrReset = "\033[0m"
		clrGray  = "\033[90m"
		clrBold  = "\033[1m"
	)
	ts := time.Now().Format("15:04:05")
	if len(args) > 0 {
		msg = msg + " | " + fmt.Sprint(args...)
	}
	line := fmt.Sprintf("%s[%s]%s %s%s%-5s%s %s", clrGray, ts, clrReset, color, clrBold, level, clrReset, msg)
	l.base.Println(line)
}
