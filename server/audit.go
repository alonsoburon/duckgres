package server

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/posthog/duckgres/server/usersecrets"
)

// QueryAuditHook is called once for every statement a session runs, whether it
// succeeds, fails or is refused by the session's QueryAccessPolicy. It is
// independent of the query log: it needs no Postgres metadata store, so it
// works with any DuckLake catalog (SQLite included) and in embedded use.
//
//   - user is the login the session authenticated as.
//   - sql is the statement text with CREATE SECRET credentials redacted. For a
//     scoped session it is the text after bare-name resolution.
//   - duration is the time spent on the statement (zero for refused ones).
//   - rows is the number of rows returned, or written for DML/COPY.
//   - err is nil on success; otherwise a *QueryAuditError carrying the
//     SQLSTATE (refused statements use 42501).
//
// The hook runs synchronously on the session's goroutine: hand slow work (disk,
// network) to a channel. A panic in the hook is recovered and logged; it never
// takes the session down.
type QueryAuditHook func(user, sql string, duration time.Duration, rows int64, err error)

// QueryAuditError is the error passed to a QueryAuditHook for a failed or
// refused statement.
type QueryAuditError struct {
	Code    string // SQLSTATE
	Message string
}

func (e *QueryAuditError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// audit reports one finished statement to Config.QueryAuditHook, if set.
func (c *clientConn) audit(start time.Time, query string, rows int64, errCode, errMsg string) {
	if c.server == nil || c.server.cfg.QueryAuditHook == nil {
		return
	}
	var err error
	if errCode != "" {
		err = &QueryAuditError{Code: errCode, Message: usersecrets.RedactErrorForLog(query, errMsg)}
	}
	var d time.Duration
	if !start.IsZero() {
		d = time.Since(start)
	}
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Query audit hook panicked.", "panic", r)
		}
	}()
	c.server.cfg.QueryAuditHook(c.username, usersecrets.RedactForLog(query), d, rows, err)
}
