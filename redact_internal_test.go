package delemark

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDedupOverlappingKeepsLongestMatch(t *testing.T) {
	t.Parallel()

	matches := []Match{
		{Start: 0, End: 5, Value: "short"},
		{Start: 3, End: 20, Value: "much-longer-match"},
	}

	deduped := dedupOverlapping(matches)

	assert.Equal(t, []Match{{Start: 3, End: 20, Value: "much-longer-match"}}, deduped)
}

func TestDedupOverlappingDropsContainedMatch(t *testing.T) {
	t.Parallel()

	matches := []Match{
		{Start: 10, End: 20, Value: "suffix"},
		{Start: 0, End: 20, Value: "full-token"},
	}

	deduped := dedupOverlapping(matches)

	assert.Equal(t, []Match{{Start: 0, End: 20, Value: "full-token"}}, deduped)
}

func TestDedupOverlappingKeepsTouchingSpans(t *testing.T) {
	t.Parallel()

	matches := []Match{
		{Start: 0, End: 5, Value: "first"},
		{Start: 5, End: 10, Value: "second"},
	}

	deduped := dedupOverlapping(matches)

	assert.Equal(t, []Match{{Start: 0, End: 5, Value: "first"}, {Start: 5, End: 10, Value: "second"}}, deduped)
}

func TestMergeOverlappingRedactionSpans(t *testing.T) {
	t.Parallel()

	matches := []Match{{Start: 0, End: 10}, {Start: 5, End: 15}, {Start: 15, End: 20}}

	merged := mergeOverlapping(matches)

	assert.Equal(t, []Match{{Start: 0, End: 15}, {Start: 15, End: 20}}, merged)
}

// TestSkipPIIRunsNoRuleWithoutKeyword pins what makes skipping "pii"
// cheap: the only rules that bypass the keyword pre-filter are tagged
// pii, so a keyword-free input runs no regex once they are skipped. A
// new keywordless rule that is not pii fails this test, and should get
// keywords or the tag.
func TestSkipPIIRunsNoRuleWithoutKeyword(t *testing.T) {
	t.Parallel()

	all, err := New()
	require.NoError(t, err)
	assert.True(t, all.alwaysRun)
	noPII, err := New(WithSkip("pii"))
	require.NoError(t, err)
	assert.False(t, noPII.alwaysRun)
}
