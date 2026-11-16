package delemark

import (
	"iter"
	"math/bits"
)

// ruleMask is a set of indices into a Redactor's rules. It has exactly
// as many words as the catalogue's rules need, which
// TestMaskSizesFitCatalogue enforces; more rules than its cap of
// len(ruleMask)*64 trip a deterministic panic in [compiledRuleSet].
// Resizing it means updating the unrolled orIn.
type ruleMask [4]uint64

func (m *ruleMask) add(i int) { m[i>>6] |= 1 << uint(i&63) }

func (m *ruleMask) orIn(other *ruleMask) {
	m[0] |= other[0]
	m[1] |= other[1]
	m[2] |= other[2]
	m[3] |= other[3]
}

// all yields the indices of m in ascending order, which is the order
// the rules run in.
func (m *ruleMask) all() iter.Seq[int] {
	return func(yield func(int) bool) {
		for w, word := range m {
			for word != 0 {
				if !yield(w*64 + bits.TrailingZeros64(word)) {
					return
				}
				word &= word - 1
			}
		}
	}
}

// ruleIndex finds the rules that can pass the keyword pre-filter without
// looking at every rule: an input usually holds few keywords, and most
// rules have none of them.
type ruleIndex struct {
	// byKeyword[k] is the rules with keyword k.
	byKeyword []ruleMask
	// keywordless is the rules without a keyword, which run on their
	// prefilter alone.
	keywordless ruleMask
}

func newRuleIndex(keywords int) ruleIndex {
	return ruleIndex{byKeyword: make([]ruleMask, keywords)}
}

// add records cr as rule i.
func (x *ruleIndex) add(i int, cr *compiledRule) {
	if cr.kwBits.empty() {
		x.keywordless.add(i)
		return
	}
	for w, word := range cr.kwBits {
		for word != 0 {
			x.byKeyword[w*64+bits.TrailingZeros64(word)].add(i)
			word &= word - 1
		}
	}
}

// candidates returns the rules without a keyword and the rules with a
// keyword of found: the rules [compiledRule.passes] can accept.
func (x *ruleIndex) candidates(found *kwMask) ruleMask {
	c := x.keywordless
	for w, word := range found {
		for word != 0 {
			c.orIn(&x.byKeyword[w*64+bits.TrailingZeros64(word)])
			word &= word - 1
		}
	}
	return c
}
