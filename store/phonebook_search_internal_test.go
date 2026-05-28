package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEscapeLikeValue_SpecialCharacters(t *testing.T) {
	assert.Equal(t, `Sales\%\_\\West`, escapeLikeValue(`Sales%_\West`))
}

func TestGetSharedGroupPatterns_EscapesLikeWildcards(t *testing.T) {
	patterns := getSharedGroupPatterns(`Sales%_\West`)

	assert.Equal(t, []string{
		`group:Sales%_\West`,
		`group:Sales\%\_\\West,%`,
		`group:%,Sales\%\_\\West,%`,
		`group:%,Sales\%\_\\West`,
	}, patterns)
}

func TestBuildVisibleCTIWhere_MacroOnlyStillEscapesGroupPatterns(t *testing.T) {
	whereClause, args := buildVisibleCTIWhere("alice", []string{`Sales%_\West`}, true)

	assert.Contains(t, whereClause, `owner_id = ?`)
	assert.Contains(t, whereClause, `type LIKE ? ESCAPE '\\'`)
	assert.Equal(t, []any{
		"alice",
		`group:Sales%_\West`,
		`group:Sales\%\_\\West,%`,
		`group:%,Sales\%\_\\West,%`,
		`group:%,Sales\%\_\\West`,
	}, args)
}