package delemark

import (
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCandidatesAreTheRulesThatCanPass checks the index against the
// check it replaces: a rule is a candidate when it has no keyword or
// shares one with the input. Each found mask is the keywords of an
// input: none, each keyword alone, every keyword, and random sets.
func TestCandidatesAreTheRulesThatCanPass(t *testing.T) {
	t.Parallel()

	keywords := compiledRuleSet().keywords
	masks := []kwMask{{}}
	var every kwMask
	for k := range keywords {
		var m kwMask
		m.set(k)
		masks = append(masks, m)
		every.set(k)
	}
	masks = append(masks, every)
	rnd := rand.New(rand.NewPCG(1, 2))
	for range 200 {
		var m kwMask
		for range 1 + rnd.IntN(6) {
			m.set(rnd.IntN(keywords))
		}
		masks = append(masks, m)
	}

	for _, skip := range [][]string{nil, {"pii"}, {"github", "aws", "connection-string"}} {
		r, err := New(WithSkip(skip...))
		require.NoError(t, err)
		for _, found := range masks {
			var want []int
			for i, cr := range r.rules {
				if cr.kwBits.empty() || found.overlaps(cr.kwBits) {
					want = append(want, i)
				}
			}
			cand := r.index.candidates(&found)
			assert.Equal(t, want, slices.Collect(cand.all()), "skip %q, found %v", skip, found)
		}
	}
}

func TestRuleMaskAllYieldsInOrder(t *testing.T) {
	t.Parallel()

	var m ruleMask
	for _, i := range []int{255, 0, 64, 63, 200} {
		m.add(i)
	}
	assert.Equal(t, []int{0, 63, 64, 200, 255}, slices.Collect(m.all()))
	var empty ruleMask
	assert.Empty(t, slices.Collect(empty.all()))
}

// TestMaskSizesFitCatalogue checks that ruleMask and kwMask have exactly
// as many words as the catalogue needs: enough to index every rule and
// every unique keyword, and no whole word to spare, since every spare
// word is scanned on each input for nothing.
func TestMaskSizesFitCatalogue(t *testing.T) {
	t.Parallel()

	rs := compiledRuleSet()
	words := func(n int) int { return (n + 63) / 64 }
	assert.Len(t, ruleMask{}, words(len(rs.rules)),
		"ruleMask must have one word per 64 of the %d rules", len(rs.rules))
	assert.Len(t, kwMask{}, words(rs.keywords),
		"kwMask must have one word per 64 of the %d unique keywords", rs.keywords)
}

// TestMaskOperationsCoverEveryWord guards the unrolled mask operations:
// after a mask is resized, each of them must still see a bit in every
// word.
func TestMaskOperationsCoverEveryWord(t *testing.T) {
	t.Parallel()

	for w := range len(kwMask{}) {
		var m kwMask
		m.set(w*64 + 63)
		assert.False(t, m.empty(), "kwMask.empty misses word %d", w)
		assert.True(t, m.overlaps(m), "kwMask.overlaps misses word %d", w)
		var dst kwMask
		dst.orIn(&m)
		assert.Equal(t, m, dst, "kwMask.orIn misses word %d", w)
	}
	for w := range len(ruleMask{}) {
		var m ruleMask
		m.add(w*64 + 63)
		assert.Equal(t, []int{w*64 + 63}, slices.Collect(m.all()), "ruleMask.all misses word %d", w)
		var dst ruleMask
		dst.orIn(&m)
		assert.Equal(t, m, dst, "ruleMask.orIn misses word %d", w)
	}
}
