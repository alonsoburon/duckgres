package server

import (
	"fmt"
	"testing"
)

type codedTestErr struct{}

func (codedTestErr) Error() string    { return "quota exceeded" }
func (codedTestErr) SQLState() string { return "53400" }

func TestEmbedderSQLState(t *testing.T) {
	if got := classifyErrorCode(fmt.Errorf("wrapped: %w", codedTestErr{})); got != "53400" {
		t.Fatalf("classifyErrorCode = %q, want 53400", got)
	}
	if got := embedderSQLState(fmt.Errorf("plain")); got != "" {
		t.Fatalf("embedderSQLState(plain) = %q, want empty", got)
	}
}
