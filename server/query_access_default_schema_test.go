package server

import (
	"database/sql"
	"strings"
	"testing"
)

// defaultSchemaPolicy models a role confined to role_a. `orders_v` exists only
// in role_a; `orders` exists only in main (outside the role's reach).
func defaultSchemaPolicy(existing map[string]bool) *QueryAccessPolicy {
	return &QueryAccessPolicy{
		ReadOnly:       true,
		AllowedSchemas: []string{"role_a"},
		DefaultSchema:  "role_a",
		RelationExists: func(schema, relation string) (bool, error) {
			return existing[strings.ToLower(schema+"."+relation)], nil
		},
	}
}

func TestAuthorizeAndRewriteResolvesBareNamesIntoDefaultSchema(t *testing.T) {
	policy := defaultSchemaPolicy(map[string]bool{"role_a.orders_v": true, "role_a.items": true})

	tests := []struct {
		query string
		want  []string
	}{
		{"SELECT * FROM orders_v", []string{"ducklake.role_a.orders_v"}},
		{"SELECT o.id FROM orders_v o JOIN items i ON i.oid = o.id", []string{"ducklake.role_a.orders_v", "ducklake.role_a.items"}},
		{"SELECT orders_v.id FROM orders_v", []string{"ducklake.role_a.orders_v"}},
		{"SELECT * FROM role_a.orders_v WHERE id IN (SELECT id FROM items)", []string{"role_a.orders_v", "ducklake.role_a.items"}},
		{"WITH x AS (SELECT * FROM orders_v) SELECT * FROM x", []string{"ducklake.role_a.orders_v", "FROM x"}},
	}
	for _, tt := range tests {
		got, err := policy.AuthorizeAndRewrite(tt.query)
		if err != nil {
			t.Errorf("AuthorizeAndRewrite(%q) error: %v", tt.query, err)
			continue
		}
		for _, want := range tt.want {
			if !strings.Contains(got, want) {
				t.Errorf("AuthorizeAndRewrite(%q) = %q, want it to contain %q", tt.query, got, want)
			}
		}
	}
}

// The bypass: the old shortcut ("treat a bare name as default_schema.name")
// approves role_a.orders while DuckDB resolves `orders` to main.orders.
func TestAuthorizeAndRewriteRejectsBareNameNotInDefaultSchema(t *testing.T) {
	policy := defaultSchemaPolicy(map[string]bool{"role_a.orders_v": true, "main.orders": true})

	for _, query := range []string{
		"SELECT * FROM orders",
		"SELECT * FROM orders_v JOIN orders ON true",
		"SELECT * FROM orders_v WHERE id IN (SELECT id FROM orders)",
		"WITH x AS (SELECT * FROM orders) SELECT * FROM x",
		"SELECT * FROM main.orders",
		"SELECT * FROM ducklake.main.orders",
		"SELECT * FROM memory.main.orders",
	} {
		if got, err := policy.AuthorizeAndRewrite(query); err == nil {
			t.Errorf("AuthorizeAndRewrite(%q) = %q, want rejection", query, got)
		}
	}
}

func TestAuthorizeAndRewriteKeepsUnchangedQueriesVerbatim(t *testing.T) {
	policy := defaultSchemaPolicy(map[string]bool{"role_a.orders_v": true})

	for _, query := range []string{
		"SELECT * FROM role_a.orders_v",
		"SELECT   1",
		"SELECT * FROM pg_class",
		"SHOW search_path",
		"WITH x AS (SELECT 1) SELECT * FROM x",
	} {
		got, err := policy.AuthorizeAndRewrite(query)
		if err != nil {
			t.Errorf("AuthorizeAndRewrite(%q) error: %v", query, err)
		}
		if got != query {
			t.Errorf("AuthorizeAndRewrite(%q) = %q, want it unchanged", query, got)
		}
	}
}

func TestAuthorizeAndRewriteFailsClosedWithoutLookup(t *testing.T) {
	policy := &QueryAccessPolicy{ReadOnly: true, AllowedSchemas: []string{"role_a"}, DefaultSchema: "role_a"}
	if got, err := policy.AuthorizeAndRewrite("SELECT * FROM orders_v"); err == nil {
		t.Errorf("bare name accepted without a RelationExists lookup: %q", got)
	}
}

func TestAuthorizeAndRewriteFailsClosedOnLookupError(t *testing.T) {
	policy := defaultSchemaPolicy(nil)
	policy.RelationExists = func(string, string) (bool, error) { return false, errLookup }
	if got, err := policy.AuthorizeAndRewrite("SELECT * FROM orders_v"); err == nil {
		t.Errorf("bare name accepted when lookup failed: %q", got)
	}
}

func TestAuthorizeAndRewriteWithoutDefaultSchemaStillRequiresQualification(t *testing.T) {
	policy := &QueryAccessPolicy{ReadOnly: true, AllowedSchemas: []string{"role_a"}}
	if _, err := policy.AuthorizeAndRewrite("SELECT * FROM orders_v"); err == nil {
		t.Error("bare name accepted without a default schema")
	}
}

func TestAuthorizeAndRewriteDoesNotRewriteWriteTargets(t *testing.T) {
	policy := defaultSchemaPolicy(map[string]bool{"role_a.orders_v": true})
	policy.ReadOnly = false
	for _, query := range []string{
		"INSERT INTO orders_v VALUES (1)",
		"UPDATE orders_v SET id = 1",
		"DELETE FROM orders_v",
		"DROP TABLE orders_v",
		"CREATE TABLE fresh (id int)",
	} {
		if got, err := policy.AuthorizeAndRewrite(query); err == nil {
			t.Errorf("AuthorizeAndRewrite(%q) = %q, want write targets to stay schema-qualified", query, got)
		}
	}
}

func TestAuthorizeStillRejectsBareNamesWithDefaultSchema(t *testing.T) {
	// Authorize cannot rewrite, so a bare name is never approved through it.
	policy := defaultSchemaPolicy(map[string]bool{"role_a.orders_v": true})
	if err := policy.Authorize("SELECT * FROM orders_v"); err == nil {
		t.Error("Authorize approved a bare name it cannot rewrite")
	}
}

var errLookup = &QueryAccessError{Reason: "lookup failed"}

// End to end against DuckDB: the lookup sees the role's schema and ignores a
// same-named relation in main, and the rewritten SQL really reads role_a.
func TestRelationLookupAndRewriteAgainstDuckDB(t *testing.T) {
	db, err := sql.Open("duckdb", ":memory:")
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	for _, stmt := range []string{
		"CREATE SCHEMA role_a",
		"CREATE TABLE main.orders AS SELECT 'main' AS src",
		"CREATE TABLE role_a.orders_base AS SELECT 'role_a' AS src",
		"CREATE VIEW role_a.orders_v AS SELECT * FROM role_a.orders_base",
		"CREATE VIEW main.orders_only_main AS SELECT 1 AS x",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}

	policy := &QueryAccessPolicy{
		ReadOnly:       true,
		AllowedSchemas: []string{"role_a"},
		DefaultSchema:  "role_a",
		RelationExists: NewRelationLookup(NewLocalExecutor(db), "memory"),
	}

	for relation, want := range map[string]bool{
		"orders_v": true, "ORDERS_BASE": true, "orders": false, "orders_only_main": false, "missing": false,
	} {
		got, err := policy.RelationExists("role_a", relation)
		if err != nil || got != want {
			t.Errorf("RelationExists(role_a, %q) = %v, %v; want %v", relation, got, err, want)
		}
	}

	if _, err := policy.AuthorizeAndRewrite("SELECT src FROM orders"); err == nil {
		t.Error("orders exists only in main and must be rejected")
	}
	if _, err := policy.AuthorizeAndRewrite("SELECT * FROM orders_only_main"); err == nil {
		t.Error("orders_only_main exists only in main and must be rejected")
	}
	// The policy qualifies with the ducklake catalog; here the data lives in
	// memory, so check the schema-qualified form it produced.
	rewritten, err := policy.AuthorizeAndRewrite("SELECT src FROM orders_v")
	if err != nil {
		t.Fatalf("AuthorizeAndRewrite: %v", err)
	}
	if !strings.Contains(rewritten, "ducklake.role_a.orders_v") {
		t.Fatalf("rewritten = %q, want ducklake.role_a.orders_v", rewritten)
	}
	var src string
	if err := db.QueryRow(strings.Replace(rewritten, "ducklake.role_a", "memory.role_a", 1)).Scan(&src); err != nil || src != "role_a" {
		t.Errorf("rewritten query read %q, %v; want role_a", src, err)
	}
}
