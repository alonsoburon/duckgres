package server

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type auditRecord struct {
	user, sql string
	duration  time.Duration
	rows      int64
	err       error
}

func newAuditConn(t *testing.T, hook QueryAuditHook) (*clientConn, func()) {
	t.Helper()
	c, cleanup := newLifecycleClientConn(t)
	c.server.cfg.QueryAuditHook = hook
	c.username = "alice"
	return c, cleanup
}

func TestQueryAuditHookSuccessAndFailure(t *testing.T) {
	var mu sync.Mutex
	var got []auditRecord
	c, cleanup := newAuditConn(t, func(user, sql string, d time.Duration, rows int64, err error) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, auditRecord{user, sql, d, rows, err})
	})
	defer cleanup()

	// No query-log sink configured: the audit hook must not depend on one.
	c.server.queryLogger = nil

	start := time.Now().Add(-50 * time.Millisecond)
	c.logQuery(start, "SELECT 1", "SELECT 1", "SELECT", 3, 0, "", "", "simple")
	c.logQuery(start, "UPDATE t SET x = 1", "UPDATE t SET x = 1", "UPDATE", 0, 5, "", "", "simple")
	c.logQuery(start, "SELECT * FROM nope", "SELECT * FROM nope", "SELECT", 0, 0, "42P01", "table nope does not exist", "extended")

	if len(got) != 3 {
		t.Fatalf("hook calls = %d, want 3", len(got))
	}
	if r := got[0]; r.user != "alice" || r.sql != "SELECT 1" || r.rows != 3 || r.err != nil || r.duration < 50*time.Millisecond {
		t.Errorf("select record = %+v", r)
	}
	if got[1].rows != 5 {
		t.Errorf("DML rows = %d, want 5 (written rows)", got[1].rows)
	}
	var ae *QueryAuditError
	if !errors.As(got[2].err, &ae) || ae.Code != "42P01" || !strings.Contains(ae.Message, "nope") {
		t.Errorf("error record = %+v", got[2].err)
	}
}

func TestQueryAuditHookRedactsSecretsAndSurvivesPanic(t *testing.T) {
	var got string
	calls := 0
	c, cleanup := newAuditConn(t, func(_, sql string, _ time.Duration, _ int64, _ error) {
		calls++
		got = sql
		if calls == 1 {
			panic("boom")
		}
	})
	defer cleanup()

	q := "CREATE SECRET s (TYPE S3, KEY_ID 'AKIA', SECRET 'hunter2-super-secret')"
	c.logQuery(time.Now(), q, q, "CREATE", 0, 0, "", "", "simple")
	c.logQuery(time.Now(), q, q, "CREATE", 0, 0, "", "", "simple")
	if calls != 2 {
		t.Fatalf("hook calls = %d, want 2 (panic must be recovered)", calls)
	}
	if strings.Contains(got, "hunter2") {
		t.Errorf("audit SQL leaked a secret: %q", got)
	}
}

func TestQueryAuditHookSeesPolicyDenials(t *testing.T) {
	var got []auditRecord
	c, cleanup := newAuditConn(t, func(user, sql string, d time.Duration, rows int64, err error) {
		got = append(got, auditRecord{user, sql, d, rows, err})
	})
	defer cleanup()
	c.queryAccessPolicy = &QueryAccessPolicy{ReadOnly: true, AllowedSchemas: []string{"role_a"}}
	c.executor = &lifecycleExecutor{}

	body := append([]byte("SELECT * FROM main.orders"), 0)
	if err := c.handleQuery(body); err != nil {
		t.Fatalf("handleQuery: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("hook calls = %d, want 1", len(got))
	}
	var ae *QueryAuditError
	if !errors.As(got[0].err, &ae) || ae.Code != "42501" {
		t.Errorf("denial err = %v, want SQLSTATE 42501", got[0].err)
	}
	if got[0].sql != "SELECT * FROM main.orders" || got[0].user != "alice" {
		t.Errorf("denial record = %+v", got[0])
	}
}

func TestQueryAuditHookUnsetIsNoop(t *testing.T) {
	c, cleanup := newAuditConn(t, nil)
	defer cleanup()
	c.logQuery(time.Now(), "SELECT 1", "SELECT 1", "SELECT", 1, 0, "", "", "simple")
}
