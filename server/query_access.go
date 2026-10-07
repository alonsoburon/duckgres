package server

import (
	"context"
	"fmt"
	"sort"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/posthog/duckgres/server/sqlcore"
)

// QueryAccessPolicy is a fail-closed SQL policy for a project-scoped user.
// A nil policy means the internal/root principal and remains unrestricted.
//
// ReadOnly separates the two scoped modes: a project reader (ReadOnly) may only
// SELECT, while a project user may additionally run DML and DDL — but only
// where every target resolves into AllowedSchemas/AllowedRelations. Neither can
// reach a relation outside the project, and neither gets the native-DuckDB
// escape hatches (arbitrary file/URL readers, secrets, settings).
type QueryAccessPolicy struct {
	ReadOnly         bool
	AllowedSchemas   []string
	AllowedRelations []string

	// DefaultSchema makes bare relation names usable: AuthorizeAndRewrite
	// qualifies a bare read reference as ducklake.<DefaultSchema>.<name>, but
	// only when RelationExists confirms <name> lives in that schema. It never
	// guesses: DuckDB itself would resolve an unqualified name through its own
	// search_path (typically main), so approving "<DefaultSchema>.<name>" while
	// executing the bare spelling would be a bypass. Empty keeps the strict
	// rule that every relation is schema-qualified.
	DefaultSchema string
	// RelationExists reports whether schema.relation (a table or view) exists
	// in the DuckLake catalog. Required for DefaultSchema; without it bare names
	// are rejected. A lookup error rejects the query.
	RelationExists func(schema, relation string) (bool, error)
}

// QueryAccessError is returned when a project-scoped principal attempts an
// operation or relation outside its policy.
type QueryAccessError struct {
	Reason string
}

func (e *QueryAccessError) Error() string {
	return "permission denied: " + e.Reason
}

var dangerousReadFunctions = map[string]struct{}{
	"current_setting":       {},
	"duckdb_secrets":        {},
	"duckdb_settings":       {},
	"getenv":                {},
	"glob":                  {},
	"http_get":              {},
	"http_post":             {},
	"nextval":               {},
	"parquet_file_metadata": {},
	"parquet_metadata":      {},
	"parquet_schema":        {},
	"query":                 {},
	"query_table":           {},
	"read_blob":             {},
	"read_csv":              {},
	"read_csv_auto":         {},
	"read_json":             {},
	"read_json_auto":        {},
	"read_ndjson":           {},
	"read_ndjson_auto":      {},
	"read_parquet":          {},
	"set_config":            {},
	"setval":                {},
	"sniff_csv":             {},
	"st_read":               {},
	"which_secret":          {},
	"write_file":            {},
}

// unqualifiedMetadataRelations are the read-only pg_catalog relations a scoped
// connection may query. The ones that describe user objects are served from
// session views narrowed to the connection's schemas (server/sessionmeta);
// pg_am, pg_proc and pg_collation describe the engine, not the data. The
// inheritance, policy, publication, rewrite, statistics and trigger relations
// are empty compatibility views (DuckDB has none of those features); psql's
// \d <table> reads them.
var unqualifiedMetadataRelations = map[string]struct{}{
	"pg_am":                    {},
	"pg_attrdef":               {},
	"pg_attribute":             {},
	"pg_class":                 {},
	"pg_collation":             {},
	"pg_constraint":            {},
	"pg_database":              {},
	"pg_description":           {},
	"pg_foreign_table":         {},
	"pg_index":                 {},
	"pg_inherits":              {},
	"pg_namespace":             {},
	"pg_partitioned_table":     {},
	"pg_policy":                {},
	"pg_proc":                  {},
	"pg_publication":           {},
	"pg_publication_namespace": {},
	"pg_publication_rel":       {},
	"pg_rewrite":               {},
	"pg_statistic_ext":         {},
	"pg_trigger":               {},
	"pg_roles":                 {},
	"pg_settings":              {},
	"pg_tables":                {},
	"pg_type":                  {},
	"pg_views":                 {},
}

var informationSchemaRelations = map[string]struct{}{
	"columns":           {},
	"key_column_usage":  {},
	"routines":          {},
	"schemata":          {},
	"sequences":         {},
	"table_constraints": {},
	"tables":            {},
	"views":             {},
}

var allowedSetVariables = map[string]struct{}{
	"application_name":                    {},
	"client_encoding":                     {},
	"datestyle":                           {},
	"extra_float_digits":                  {},
	"idle_in_transaction_session_timeout": {},
	"lock_timeout":                        {},
	"statement_timeout":                   {},
	"timezone":                            {},
}

var allowedShowVariables = map[string]struct{}{
	"application_name":              {},
	"client_encoding":               {},
	"datestyle":                     {},
	"default_transaction_isolation": {},
	"integer_datetimes":             {},
	"max_index_keys":                {},
	"search_path":                   {},
	"server_version":                {},
	"server_version_num":            {},
	"standard_conforming_strings":   {},
	"timezone":                      {},
	"transaction_isolation":         {},
	"transaction_read_only":         {},
}

// queryAuthorizer walks one parsed statement against a project policy. It is
// default-deny throughout: a statement or object shape it does not explicitly
// recognize is refused rather than passed through.
type queryAuthorizer struct {
	// writable is set for a project user (QueryAccessPolicy.ReadOnly == false).
	// It only ever unlocks statements whose targets are still scope-checked —
	// it never widens the set of reachable relations.
	writable         bool
	allowedSchemas   map[string]struct{}
	allowedRelations map[string]struct{}

	// Bare-name resolution (AuthorizeAndRewrite only). defaultSchema == ""
	// means bare names are rejected.
	defaultSchema  string
	relationExists func(schema, relation string) (bool, error)
	lookups        map[string]bool
	rewritten      bool
}

// Authorize verifies that every persistent relation a query touches is owned by
// the project, and that the statement itself is within the principal's mode: a
// project reader may only read, a project user may also write. Native DuckDB
// fallback is deliberately unavailable to scoped users because an unparsed
// statement cannot be authorized safely.
func (p *QueryAccessPolicy) Authorize(query string) error {
	_, err := p.authorize(query, false)
	return err
}

// AuthorizeAndRewrite is Authorize plus bare-name resolution: when the policy
// has a DefaultSchema, every bare read reference that exists in that schema is
// qualified in the parsed tree and the SQL to EXECUTE is returned (deparsed from
// the rewritten tree). Callers must run the returned SQL, never the original,
// otherwise DuckDB would resolve the bare name on its own.
//
// A query that needed no rewrite is returned verbatim, so the common
// schema-qualified path is untouched. A bare name that does not exist in the
// default schema is rejected, whatever it might resolve to elsewhere.
func (p *QueryAccessPolicy) AuthorizeAndRewrite(query string) (string, error) {
	return p.authorize(query, true)
}

func (p *QueryAccessPolicy) authorize(query string, rewrite bool) (string, error) {
	if p == nil {
		return query, nil
	}
	if handled, err := authorizeProjectUse(query); handled {
		return query, err
	}
	az := &queryAuthorizer{
		writable:         !p.ReadOnly,
		allowedSchemas:   normalizedSet(p.AllowedSchemas),
		allowedRelations: normalizedSet(p.AllowedRelations),
	}
	if rewrite && strings.TrimSpace(p.DefaultSchema) != "" {
		az.defaultSchema = strings.ToLower(strings.TrimSpace(p.DefaultSchema))
		az.relationExists = p.RelationExists
		az.lookups = make(map[string]bool)
	}
	tree, err := pg_query.Parse(query)
	if err != nil {
		return query, &QueryAccessError{Reason: az.unparsedReason()}
	}

	for _, raw := range tree.Stmts {
		if raw == nil || raw.Stmt == nil {
			continue
		}
		if err := az.authorizeStatement(raw.Stmt); err != nil {
			return query, err
		}

		if err := az.walk(raw.Stmt, nil); err != nil {
			return query, err
		}
	}
	if !az.rewritten {
		return query, nil
	}
	rewritten, err := pg_query.Deparse(tree)
	if err != nil {
		return query, &QueryAccessError{Reason: "could not resolve unqualified relation names"}
	}
	return rewritten, nil
}

func (az *queryAuthorizer) unparsedReason() string {
	if az.writable {
		// DuckDB-only spellings (CREATE OR REPLACE TABLE, FROM-first SELECT)
		// land here: the parser is the authorization boundary, so anything it
		// cannot describe cannot be scope-checked.
		return "project connections only accept PostgreSQL-compatible queries"
	}
	return "project connections only accept PostgreSQL-compatible read queries"
}

func (az *queryAuthorizer) walk(node *pg_query.Node, visibleCTEs map[string]struct{}) error {
	if node == nil {
		return nil
	}
	if err := az.authorizeWriteNode(node); err != nil {
		return err
	}
	if rv := node.GetRangeVar(); rv != nil {
		if err := az.authorizeRangeVar(rv, visibleCTEs); err != nil {
			return err
		}
	}
	if fc := node.GetFuncCall(); fc != nil {
		name := functionName(fc)
		if dangerousFunction(name) && !allowedSettingLookup(name, fc) {
			return &QueryAccessError{Reason: fmt.Sprintf("function %q is unavailable to project connections", name)}
		}
	}
	// A WITH clause on ANY statement (not just SELECT) introduces names that
	// are legal unqualified references in the body. Handle them uniformly so
	// `WITH x AS (...) INSERT INTO team.t SELECT * FROM x` is not rejected for
	// failing the schema-qualification rule on `x`.
	if inner, withClause := statementWithClause(node); withClause != nil {
		return az.authorizeWithClause(inner, withClause, visibleCTEs)
	}
	return az.walkChildren(node.ProtoReflect(), "", visibleCTEs)
}

// statementWithClause returns the statement message behind node together with
// its WITH clause, for the statement kinds that can carry one.
func statementWithClause(node *pg_query.Node) (protoreflect.Message, *pg_query.WithClause) {
	switch n := node.Node.(type) {
	case *pg_query.Node_SelectStmt:
		return n.SelectStmt.ProtoReflect(), n.SelectStmt.GetWithClause()
	case *pg_query.Node_InsertStmt:
		return n.InsertStmt.ProtoReflect(), n.InsertStmt.GetWithClause()
	case *pg_query.Node_UpdateStmt:
		return n.UpdateStmt.ProtoReflect(), n.UpdateStmt.GetWithClause()
	case *pg_query.Node_DeleteStmt:
		return n.DeleteStmt.ProtoReflect(), n.DeleteStmt.GetWithClause()
	case *pg_query.Node_MergeStmt:
		return n.MergeStmt.ProtoReflect(), n.MergeStmt.GetWithClause()
	}
	return nil, nil
}

func (az *queryAuthorizer) authorizeWithClause(statement protoreflect.Message, withClause *pg_query.WithClause, outerCTEs map[string]struct{}) error {
	visibleCTEs := copyStringSet(outerCTEs)
	if withClause.Recursive {
		for _, cteNode := range withClause.Ctes {
			if cte := cteNode.GetCommonTableExpr(); cte != nil {
				visibleCTEs[strings.ToLower(cte.Ctename)] = struct{}{}
			}
		}
	}
	for _, cteNode := range withClause.Ctes {
		cte := cteNode.GetCommonTableExpr()
		if cte == nil {
			continue
		}
		if err := az.walk(cte.Ctequery, visibleCTEs); err != nil {
			return err
		}
		if !withClause.Recursive {
			visibleCTEs[strings.ToLower(cte.Ctename)] = struct{}{}
		}
	}
	return az.walkChildren(statement, "with_clause", visibleCTEs)
}

func (az *queryAuthorizer) walkChildren(message protoreflect.Message, skippedField protoreflect.Name, visibleCTEs map[string]struct{}) error {
	var denied error
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.Name() == skippedField {
			return true
		}
		if field.IsList() && field.Kind() == protoreflect.MessageKind {
			list := value.List()
			for index := 0; index < list.Len(); index++ {
				if err := az.walkMessage(list.Get(index).Message(), visibleCTEs); err != nil {
					denied = err
					return false
				}
			}
			return true
		}
		if field.Kind() == protoreflect.MessageKind {
			denied = az.walkMessage(value.Message(), visibleCTEs)
			return denied == nil
		}
		return true
	})
	return denied
}

func (az *queryAuthorizer) walkMessage(message protoreflect.Message, visibleCTEs map[string]struct{}) error {
	switch typed := message.Interface().(type) {
	case *pg_query.Node:
		return az.walk(typed, visibleCTEs)
	case *pg_query.RangeVar:
		// Some RangeVars hang off a statement as a bare field rather than a
		// Node (InsertStmt.relation, Constraint.pktable, …), which the
		// Node-only walk would step straight past. This catches all of them.
		//
		// Note this is NOT a "write target" position: walk() descends into a
		// Node's own oneof field, so ordinary read references reach here too.
		// Write targets get their stricter check by name, in
		// authorizeWriteStatement — this is the defense-in-depth net for
		// positions that check does not enumerate.
		return az.authorizeRangeVar(typed, visibleCTEs)
	}
	return az.walkChildren(message, "", visibleCTEs)
}

func copyStringSet(values map[string]struct{}) map[string]struct{} {
	copy := make(map[string]struct{}, len(values))
	for value := range values {
		copy[value] = struct{}{}
	}
	return copy
}

func authorizeProjectUse(query string) (bool, error) {
	trimmed := strings.TrimSpace(stripLeadingComments(query))
	parts := strings.Fields(trimmed)
	if len(parts) == 0 || !strings.EqualFold(parts[0], "USE") {
		return false, nil
	}
	if len(parts) != 2 {
		return true, &QueryAccessError{Reason: "project connections may only select the ducklake catalog"}
	}

	catalog := strings.TrimSpace(strings.TrimSuffix(parts[1], ";"))
	if len(catalog) >= 2 && catalog[0] == '"' && catalog[len(catalog)-1] == '"' {
		catalog = strings.ReplaceAll(catalog[1:len(catalog)-1], `""`, `"`)
	}
	if !strings.EqualFold(catalog, "ducklake") {
		return true, &QueryAccessError{Reason: fmt.Sprintf("catalog %q is not available to this project", catalog)}
	}
	return true, nil
}

// allowedSettingLookup permits current_setting('<name>') when <name> is a
// string literal naming one of the variables SHOW already exposes (pgjdbc reads
// max_index_keys this way). Any other argument shape stays blocked: a computed
// name could reach engine settings such as S3 keys.
func allowedSettingLookup(name string, call *pg_query.FuncCall) bool {
	if name != "current_setting" || len(call.Args) < 1 || len(call.Args) > 2 {
		return false
	}
	c := call.Args[0].GetAConst()
	if c == nil || c.GetSval() == nil {
		return false
	}
	_, ok := allowedShowVariables[strings.ToLower(c.GetSval().Sval)]
	return ok
}

func dangerousFunction(name string) bool {
	if _, dangerous := dangerousReadFunctions[name]; dangerous {
		return true
	}
	return strings.HasPrefix(name, "read_") ||
		strings.HasPrefix(name, "duckdb_") ||
		strings.HasPrefix(name, "http_") ||
		strings.HasPrefix(name, "mysql_") ||
		strings.HasPrefix(name, "postgres_") ||
		strings.HasPrefix(name, "pragma_") ||
		strings.HasPrefix(name, "sqlite_") ||
		strings.HasSuffix(name, "_scan")
}

// authorizeWriteNode rejects mutation anywhere in the tree for a read-only
// principal — including inside a CTE, where a writable CTE executes even under
// LIMIT 0. A project user skips this gate; its writes are constrained instead
// by the scope check every write target goes through.
func (az *queryAuthorizer) authorizeWriteNode(node *pg_query.Node) error {
	if az.writable {
		return nil
	}
	if selectStmt := node.GetSelectStmt(); selectStmt != nil && selectStmt.IntoClause != nil {
		return &QueryAccessError{Reason: "project connections are read-only"}
	}
	switch node.Node.(type) {
	case *pg_query.Node_InsertStmt, *pg_query.Node_UpdateStmt, *pg_query.Node_DeleteStmt, *pg_query.Node_MergeStmt:
		return &QueryAccessError{Reason: "project connections are read-only"}
	default:
		return nil
	}
}

func (az *queryAuthorizer) authorizeStatement(node *pg_query.Node) error {
	if show := node.GetVariableShowStmt(); show != nil {
		if _, allowed := allowedShowVariables[strings.ToLower(show.Name)]; allowed {
			return nil
		}
		return &QueryAccessError{Reason: fmt.Sprintf("setting %q is unavailable to project connections", show.Name)}
	}
	if set := node.GetVariableSetStmt(); set != nil {
		if _, allowed := allowedSetVariables[strings.ToLower(set.Name)]; allowed {
			return nil
		}
		return &QueryAccessError{Reason: fmt.Sprintf("setting %q is unavailable to project connections", set.Name)}
	}
	switch node.Node.(type) {
	case *pg_query.Node_SelectStmt:
		// SELECT … INTO creates and populates a relation. A read-only
		// principal is stopped by authorizeWriteNode during the walk; for a
		// project user the new relation is a write target and is scoped here.
		if into := node.GetSelectStmt().GetIntoClause(); into != nil && az.writable {
			return az.authorizeWriteTarget(into.GetRel())
		}
		return nil
	case *pg_query.Node_TransactionStmt:
		return nil
	}
	if !az.writable {
		return &QueryAccessError{Reason: "project connections are read-only"}
	}
	return az.authorizeWriteStatement(node)
}

// authorizeWriteStatement is the project user's statement allowlist. Each entry
// must name EVERY relation it mutates so authorizeWriteTarget can scope it —
// the generic walk is not sufficient here, because its RangeVar check is the
// lenient read-position one (it honours CTE names and the unqualified
// pg_catalog compat names, neither of which a write target may use).
//
// Anything absent — CREATE SCHEMA, ALTER TABLE … SET SCHEMA, GRANT, cursors,
// prepared statements, ATTACH, EXPLAIN — stays denied, because it either
// escapes the project's namespaces or cannot be scoped. Adding a case REQUIRES
// enumerating that statement's targets here.
func (az *queryAuthorizer) authorizeWriteStatement(node *pg_query.Node) error {
	switch typed := node.Node.(type) {
	case *pg_query.Node_InsertStmt:
		return az.authorizeWriteTarget(typed.InsertStmt.GetRelation())
	case *pg_query.Node_UpdateStmt:
		return az.authorizeWriteTarget(typed.UpdateStmt.GetRelation())
	case *pg_query.Node_DeleteStmt:
		return az.authorizeWriteTarget(typed.DeleteStmt.GetRelation())
	case *pg_query.Node_MergeStmt:
		return az.authorizeWriteTarget(typed.MergeStmt.GetRelation())
	case *pg_query.Node_TruncateStmt:
		for _, relation := range typed.TruncateStmt.GetRelations() {
			if err := az.authorizeWriteTarget(relation.GetRangeVar()); err != nil {
				return err
			}
		}
		return nil
	case *pg_query.Node_CreateStmt:
		return az.authorizeWriteTarget(typed.CreateStmt.GetRelation())
	case *pg_query.Node_CreateTableAsStmt:
		return az.authorizeWriteTarget(typed.CreateTableAsStmt.GetInto().GetRel())
	case *pg_query.Node_ViewStmt:
		return az.authorizeWriteTarget(typed.ViewStmt.GetView())
	case *pg_query.Node_IndexStmt:
		return az.authorizeWriteTarget(typed.IndexStmt.GetRelation())
	case *pg_query.Node_CreateSeqStmt:
		return az.authorizeWriteTarget(typed.CreateSeqStmt.GetSequence())
	case *pg_query.Node_AlterSeqStmt:
		return az.authorizeWriteTarget(typed.AlterSeqStmt.GetSequence())
	case *pg_query.Node_AlterTableStmt:
		return az.authorizeWriteTarget(typed.AlterTableStmt.GetRelation())
	case *pg_query.Node_DropStmt:
		return az.authorizeDropStatement(typed.DropStmt)
	case *pg_query.Node_RenameStmt:
		return az.authorizeRenameStatement(typed.RenameStmt)
	case *pg_query.Node_CopyStmt:
		return az.authorizeCopyStatement(typed.CopyStmt)
	}
	return &QueryAccessError{Reason: "this statement is unavailable to project connections"}
}

// scopedDropObjectTypes are the object kinds a project user may DROP. They are
// exactly the kinds whose names are schema-qualified, so the target can be
// proven to belong to the project.
var scopedDropObjectTypes = map[pg_query.ObjectType]struct{}{
	pg_query.ObjectType_OBJECT_TABLE:    {},
	pg_query.ObjectType_OBJECT_VIEW:     {},
	pg_query.ObjectType_OBJECT_INDEX:    {},
	pg_query.ObjectType_OBJECT_SEQUENCE: {},
}

// scopedRenameObjectTypes are the RENAME targets a project user may issue. All
// of them carry a RangeVar the walk scope-checks, and none can move an object
// between schemas (that is ALTER … SET SCHEMA, which stays denied).
var scopedRenameObjectTypes = map[pg_query.ObjectType]struct{}{
	pg_query.ObjectType_OBJECT_TABLE:    {},
	pg_query.ObjectType_OBJECT_VIEW:     {},
	pg_query.ObjectType_OBJECT_INDEX:    {},
	pg_query.ObjectType_OBJECT_SEQUENCE: {},
	pg_query.ObjectType_OBJECT_COLUMN:   {},
}

// authorizeDropStatement scopes DROP by hand: its targets are dotted name
// lists, not RangeVars, so the generic walk never sees them.
func (az *queryAuthorizer) authorizeDropStatement(stmt *pg_query.DropStmt) error {
	if _, ok := scopedDropObjectTypes[stmt.GetRemoveType()]; !ok {
		return &QueryAccessError{Reason: "this statement is unavailable to project connections"}
	}
	for _, object := range stmt.GetObjects() {
		catalog, schema, relation, ok := qualifiedNameParts(object)
		if !ok {
			return &QueryAccessError{Reason: "project connections may only drop schema-qualified project objects"}
		}
		if err := az.authorizeQualifiedRelation(catalog, schema, relation); err != nil {
			return err
		}
	}
	return nil
}

func (az *queryAuthorizer) authorizeRenameStatement(stmt *pg_query.RenameStmt) error {
	if _, ok := scopedRenameObjectTypes[stmt.GetRenameType()]; !ok {
		return &QueryAccessError{Reason: "this statement is unavailable to project connections"}
	}
	// Without a relation the target would be named by a bare string (a schema
	// or database), which is not a project-scopable object.
	if stmt.GetRelation() == nil {
		return &QueryAccessError{Reason: "project connections may only rename schema-qualified project objects"}
	}
	return az.authorizeWriteTarget(stmt.GetRelation())
}

// authorizeCopyStatement admits only COPY <relation> FROM STDIN. The file and
// PROGRAM forms read or write outside the project entirely, and COPY … TO
// STDOUT is an export path no scoped mode has (a project reader cannot use it
// either).
func (az *queryAuthorizer) authorizeCopyStatement(stmt *pg_query.CopyStmt) error {
	if !stmt.GetIsFrom() {
		return &QueryAccessError{Reason: "project connections may only COPY into a project relation from STDIN"}
	}
	if stmt.GetIsProgram() || stmt.GetFilename() != "" {
		return &QueryAccessError{Reason: "project connections may only COPY from STDIN"}
	}
	if stmt.GetRelation() == nil {
		return &QueryAccessError{Reason: "project connections may only COPY into a project relation from STDIN"}
	}
	return az.authorizeWriteTarget(stmt.GetRelation())
}

// qualifiedNameParts flattens a dotted-name Node list (DropStmt object form)
// into catalog/schema/relation. Anything that is not a plain 1-3 part string
// list is reported as unusable, and the caller fails closed.
func qualifiedNameParts(object *pg_query.Node) (catalog, schema, relation string, ok bool) {
	list := object.GetList()
	if list == nil {
		return "", "", "", false
	}
	parts := make([]string, 0, len(list.Items))
	for _, item := range list.Items {
		str := item.GetString_()
		if str == nil {
			return "", "", "", false
		}
		parts = append(parts, str.Sval)
	}
	switch len(parts) {
	case 2:
		return "", parts[0], parts[1], true
	case 3:
		return parts[0], parts[1], parts[2], true
	default:
		// A bare name would resolve through the search path, which scoped
		// connections do not have — require qualification.
		return "", "", "", false
	}
}

// authorizeWriteTarget scopes the relation a statement WRITES to. It is
// deliberately stricter than authorizeRangeVar: the target must be
// schema-qualified, full stop.
//
// The two escape hatches authorizeRangeVar grants a bare name are both unsound
// for a target. A CTE name is sound in a READ position because a defined CTE
// shadows any base relation of the same name — the reference provably binds to
// the CTE. A write target does NOT bind to the CTE (a CTE is not insertable),
// so it falls through to the session search_path (sessionmeta leaves it at
// `main,memory.main`) and would reach a real relation outside the project:
// `WITH shared AS (SELECT 1) INSERT INTO shared VALUES (1)` would write
// ducklake.main.shared. The unqualified pg_catalog compat names are unsound for
// the same reason. Both are reads-only concessions.
func (az *queryAuthorizer) authorizeWriteTarget(rv *pg_query.RangeVar) error {
	if rv == nil {
		// A statement in the write allowlist with no resolvable target is a
		// tree shape this authorizer does not understand. Fail closed.
		return &QueryAccessError{Reason: "this statement is unavailable to project connections"}
	}
	if strings.TrimSpace(rv.Schemaname) == "" {
		return &QueryAccessError{Reason: fmt.Sprintf("relation %q must be schema-qualified", rv.Relname)}
	}
	return az.authorizeQualifiedRelation(rv.Catalogname, rv.Schemaname, rv.Relname)
}

func (az *queryAuthorizer) authorizeRangeVar(rv *pg_query.RangeVar, cteNames map[string]struct{}) error {
	schema := strings.ToLower(rv.Schemaname)
	relation := strings.ToLower(rv.Relname)
	if schema == "" {
		if rv.Catalogname != "" {
			return &QueryAccessError{Reason: fmt.Sprintf("relation %q must be schema-qualified", rv.Relname)}
		}
		if _, ok := cteNames[relation]; ok {
			return nil
		}
		if _, ok := unqualifiedMetadataRelations[relation]; ok {
			return nil
		}
		if az.defaultSchema != "" {
			return az.resolveBareRelation(rv)
		}
		return &QueryAccessError{Reason: fmt.Sprintf("relation %q must be schema-qualified", rv.Relname)}
	}
	return az.authorizeQualifiedRelation(rv.Catalogname, rv.Schemaname, rv.Relname)
}

// resolveBareRelation qualifies a bare read reference into the default schema,
// in place, if (and only if) the relation exists there. Anything else is
// rejected, including names that exist only outside the role's schemas.
func (az *queryAuthorizer) resolveBareRelation(rv *pg_query.RangeVar) error {
	notFound := &QueryAccessError{Reason: fmt.Sprintf("relation %q does not exist in schema %q; qualify it with its schema", rv.Relname, az.defaultSchema)}
	if az.relationExists == nil {
		return &QueryAccessError{Reason: fmt.Sprintf("relation %q must be schema-qualified", rv.Relname)}
	}
	key := az.defaultSchema + "." + strings.ToLower(rv.Relname)
	exists, cached := az.lookups[key]
	if !cached {
		var err error
		exists, err = az.relationExists(az.defaultSchema, rv.Relname)
		if err != nil {
			return &QueryAccessError{Reason: fmt.Sprintf("could not resolve relation %q", rv.Relname)}
		}
		az.lookups[key] = exists
	}
	if !exists {
		return notFound
	}
	if err := az.authorizeQualifiedRelation("ducklake", az.defaultSchema, rv.Relname); err != nil {
		return err
	}
	rv.Catalogname = "ducklake"
	rv.Schemaname = az.defaultSchema
	az.rewritten = true
	return nil
}

func (az *queryAuthorizer) authorizeQualifiedRelation(catalogName, schemaName, relationName string) error {
	catalog := strings.ToLower(catalogName)
	schema := strings.ToLower(schemaName)
	relation := strings.ToLower(relationName)
	if catalog != "" && catalog != "ducklake" {
		return &QueryAccessError{Reason: fmt.Sprintf("catalog %q is not available to this project", catalogName)}
	}
	if schema == "information_schema" {
		if _, ok := informationSchemaRelations[relation]; ok {
			return nil
		}
		return &QueryAccessError{Reason: fmt.Sprintf("catalog relation %q is unavailable to project connections", relation)}
	}
	if schema == "pg_catalog" {
		if _, ok := unqualifiedMetadataRelations[relation]; ok {
			return nil
		}
		return &QueryAccessError{Reason: fmt.Sprintf("catalog relation %q is unavailable to project connections", relation)}
	}
	if _, ok := az.allowedSchemas[schema]; ok {
		return nil
	}
	qualified := schema + "." + relation
	if _, ok := az.allowedRelations[qualified]; ok {
		return nil
	}
	return &QueryAccessError{Reason: fmt.Sprintf("relation %q is not available to this project", qualified)}
}

func functionName(call *pg_query.FuncCall) string {
	if call == nil || len(call.Funcname) == 0 {
		return ""
	}
	last := call.Funcname[len(call.Funcname)-1].GetString_()
	if last == nil {
		return ""
	}
	return strings.ToLower(last.Sval)
}

func normalizedSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[strings.ToLower(strings.TrimSpace(value))] = struct{}{}
	}
	return result
}

// NormalizeQueryAccessPolicy makes policy snapshots deterministic for tests,
// logging, and cross-protocol conversion.
func NormalizeQueryAccessPolicy(policy QueryAccessPolicy) QueryAccessPolicy {
	policy.AllowedSchemas = append([]string(nil), policy.AllowedSchemas...)
	policy.AllowedRelations = append([]string(nil), policy.AllowedRelations...)
	sort.Strings(policy.AllowedSchemas)
	sort.Strings(policy.AllowedRelations)
	return policy
}

// NewRelationLookup returns a QueryAccessPolicy.RelationExists backed by the
// session's executor: it asks DuckDB whether schema.relation is a table or view
// in catalog (normally "ducklake"). It runs before the client's statement, on
// the same session, so it sees exactly what that statement would.
func NewRelationLookup(exec sqlcore.QueryExecutor, catalog string) func(schema, relation string) (bool, error) {
	const lookupSQL = `
		SELECT 1 FROM duckdb_tables()
		WHERE database_name = ? AND lower(schema_name) = lower(?) AND lower(table_name) = lower(?)
		UNION ALL
		SELECT 1 FROM duckdb_views()
		WHERE database_name = ? AND lower(schema_name) = lower(?) AND lower(view_name) = lower(?)
		LIMIT 1`
	return func(schema, relation string) (bool, error) {
		rows, err := exec.QueryContext(context.Background(), lookupSQL, catalog, schema, relation, catalog, schema, relation)
		if err != nil {
			return false, err
		}
		defer func() { _ = rows.Close() }()
		found := rows.Next()
		return found, rows.Err()
	}
}
