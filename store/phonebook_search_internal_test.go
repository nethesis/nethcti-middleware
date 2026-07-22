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

func TestBuildLegacySearchClauses_EscapesLikeWildcards(t *testing.T) {
	ctiArgs, centralizedArgs, ctiClause, centralizedClause := buildLegacySearchClauses("", `Sales%_\West`)

	assert.Contains(t, ctiClause, `LIKE ? ESCAPE '\\'`)
	assert.Contains(t, centralizedClause, `LIKE ? ESCAPE '\\'`)
	assert.Equal(t, []any{
		// base name + company, then workphone, workphone2, homephone,
		// cellphone, cellphone2, otherphone, extension, notes (the secondary
		// phone columns and otherphone were added with the extended fields).
		`%Sales\%\_\\West%`,
		`%Sales\%\_\\West%`,
		`%Sales\%\_\\West%`,
		`%Sales\%\_\\West%`,
		`%Sales\%\_\\West%`,
		`%Sales\%\_\\West%`,
		`%Sales\%\_\\West%`,
		`%Sales\%\_\\West%`,
		`%Sales\%\_\\West%`,
		`%Sales\%\_\\West%`,
	}, ctiArgs)
	assert.Equal(t, []any{
		`%Sales\%\_\\West%`,
		`%Sales\%\_\\West%`,
		`%Sales\%\_\\West%`,
		`%Sales\%\_\\West%`,
		`%Sales\%\_\\West%`,
		`%Sales\%\_\\West%`,
	}, centralizedArgs)
}

func TestLegacyFlatOrderByClause(t *testing.T) {
	// The empty/unknown sort MUST keep the legacy ordering: existing frontends
	// (nethvoice-cti, phone-island) do not send a sort param yet, so changing
	assert.Equal(t, "ORDER BY company ASC, name ASC", legacyFlatOrderByClause(""))
	assert.Equal(t, "ORDER BY company ASC, name ASC", legacyFlatOrderByClause("bogus"))

	assert.Equal(t,
		"ORDER BY (firstname IS NULL OR firstname = '') ASC, "+
			"COALESCE(NULLIF(firstname, ''), "+flatDisplayKey+") ASC",
		legacyFlatOrderByClause("firstname"))

	lastnameClause := "ORDER BY (lastname IS NULL OR lastname = '') ASC, " +
		"COALESCE(NULLIF(lastname, ''), " + flatDisplayKey + ") ASC"
	assert.Equal(t, lastnameClause, legacyFlatOrderByClause("lastname"))
	assert.Equal(t, lastnameClause, legacyFlatOrderByClause("surname"))
	assert.Equal(t, lastnameClause, legacyFlatOrderByClause("LASTNAME"))

	assert.Equal(t,
		"ORDER BY COALESCE(NULLIF(company, ''), "+flatDisplayKey+") ASC",
		legacyFlatOrderByClause("company"))

	assert.Equal(t, "ORDER BY "+flatDisplayKey+" ASC", legacyFlatOrderByClause("displayname"))
	assert.Equal(t, "ORDER BY "+flatDisplayKey+" ASC", legacyFlatOrderByClause("name"))
}

func TestLegacyListOrderByClause(t *testing.T) {
	assert.Equal(t, "ORDER BY sort_name ASC", legacyListOrderByClause(""))
	assert.Equal(t, "ORDER BY sort_name ASC", legacyListOrderByClause("bogus"))
	assert.Equal(t, "ORDER BY sort_name ASC", legacyListOrderByClause("displayname"))
	assert.Equal(t, "ORDER BY sort_name ASC", legacyListOrderByClause("name"))

	assert.Equal(t,
		"ORDER BY (firstname IS NULL OR firstname = '') ASC, "+
			"COALESCE(NULLIF(firstname, ''), sort_name) ASC",
		legacyListOrderByClause("firstname"))

	lastnameClause := "ORDER BY (lastname IS NULL OR lastname = '') ASC, " +
		"COALESCE(NULLIF(lastname, ''), sort_name) ASC"
	assert.Equal(t, lastnameClause, legacyListOrderByClause("lastname"))
	assert.Equal(t, lastnameClause, legacyListOrderByClause("surname"))

	assert.Equal(t, "ORDER BY company ASC, sort_name ASC", legacyListOrderByClause("company"))
}

func TestBuildLegacySearchClauses_ViewGuards(t *testing.T) {
	const personGuard = "name IS NOT NULL AND name != '' AND name != '-'"
	const companyGuard = "company IS NOT NULL AND company != '' AND company != '-'"

	t.Run("person view guards out company rows", func(t *testing.T) {
		_, _, ctiClause, centralizedClause := buildLegacySearchClauses("person", "acme")

		assert.Contains(t, ctiClause, personGuard+" AND (")
		assert.Contains(t, centralizedClause, personGuard+" AND (")
		assert.NotContains(t, ctiClause, companyGuard)
	})

	t.Run("company view guards out person rows without company", func(t *testing.T) {
		_, _, ctiClause, centralizedClause := buildLegacySearchClauses("company", "acme")

		assert.Contains(t, ctiClause, companyGuard+" AND (")
		assert.Contains(t, centralizedClause, companyGuard+" AND (")
		assert.NotContains(t, ctiClause, personGuard)
	})

	t.Run("default view applies no guard", func(t *testing.T) {
		_, _, ctiClause, centralizedClause := buildLegacySearchClauses("", "acme")

		assert.NotContains(t, ctiClause, personGuard)
		assert.NotContains(t, ctiClause, companyGuard)
		assert.NotContains(t, centralizedClause, personGuard)
		assert.NotContains(t, centralizedClause, companyGuard)
	})
}

func TestBuildVisibleCentralizedWhere_NoGroupsOnlyNonGroupScoped(t *testing.T) {
	clause, args := buildVisibleCentralizedWhere(nil)

	assert.Equal(t, `type NOT LIKE ? ESCAPE '\\'`, clause)
	assert.Equal(t, []any{"group:%"}, args)
}

func TestBuildVisibleCentralizedWhere_WithGroupsAddsMembershipPatterns(t *testing.T) {
	clause, args := buildVisibleCentralizedWhere([]string{`Sales%_\West`})

	assert.Contains(t, clause, `type NOT LIKE ? ESCAPE '\\'`)
	assert.Contains(t, clause, `type = ? OR type LIKE ? ESCAPE '\\'`)
	assert.Equal(t, []any{
		"group:%",
		`group:Sales%_\West`,
		`group:Sales\%\_\\West,%`,
		`group:%,Sales\%\_\\West,%`,
		`group:%,Sales\%\_\\West`,
	}, args)
}

func TestBuildLegacyVisibilityClauses_CentralizedUsesItsOwnTaxonomy(t *testing.T) {
	t.Run("all keeps centralized rows visible", func(t *testing.T) {
		ctiClause, ctiArgs, centralizedClause, centralizedArgs := buildLegacyVisibilityClauses("all")

		assert.Equal(t, "1 = 1", ctiClause)
		assert.Nil(t, ctiArgs)
		assert.Equal(t, "1 = 1", centralizedClause)
		assert.Nil(t, centralizedArgs)
	})

	t.Run("public still includes centralized rows", func(t *testing.T) {
		ctiClause, ctiArgs, centralizedClause, centralizedArgs := buildLegacyVisibilityClauses("public")

		assert.Equal(t, "type = ?", ctiClause)
		assert.Equal(t, []any{"public"}, ctiArgs)
		assert.Equal(t, "1 = 1", centralizedClause)
		assert.Nil(t, centralizedArgs)
	})

	t.Run("private excludes centralized rows, group gates them by scope", func(t *testing.T) {
		_, _, centralizedPrivateClause, centralizedPrivateArgs := buildLegacyVisibilityClauses("private")
		_, _, centralizedGroupClause, centralizedGroupArgs := buildLegacyVisibilityClauses("group")

		// No private concept in the centralized phonebook.
		assert.Equal(t, "1 = 0", centralizedPrivateClause)
		assert.Nil(t, centralizedPrivateArgs)
		// Group view keeps only group-scoped centralized rows (membership is enforced
		// separately by buildVisibleCentralizedWhere).
		assert.Equal(t, "type LIKE ?", centralizedGroupClause)
		assert.Equal(t, []any{"group:%"}, centralizedGroupArgs)
	})
}
