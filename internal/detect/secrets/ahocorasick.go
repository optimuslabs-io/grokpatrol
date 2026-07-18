package secrets

// A single-pass multi-string matcher for the keyword prefilter.
//
// gitleaks gates each rule's (expensive) regex behind a cheap check: does the
// blob contain any of the rule's keywords at all? The union of those keywords
// across the 222-rule corpus is ~244 distinct strings. The obvious
// implementation -- one strings.Contains sweep per keyword -- is what shipped
// first, and profiling showed it WAS the cost of a content scan: 244 full
// passes over every blob, ~20 MB/s, single-threaded, dwarfing the regex work it
// exists to avoid (rules.go's file comment named this as the known gap).
//
// Aho-Corasick answers "which of these fixed strings appear" in ONE pass,
// O(len(blob)) regardless of keyword count. The automaton is built once (under
// the same sync.Once as rule compilation) and reused for every blob. It is a
// pure prefilter: it decides only whether a rule's regex runs, never whether a
// finding is reported, so it holds no secret bytes and leaks nothing -- the same
// contract as the substring sweep it replaces, and it returns the same answers
// (the leak tests and the scan tests both pin that).
//
// The automaton is materialized as a dense DFA: next[state<<8 | b] is the state
// after reading byte b, with failure links already folded in, so scanning is one
// array load per input byte and no failure-link chasing at match time.

type acMatcher struct {
	// next is the flattened transition table: next[int(state)<<8 | b] gives the
	// next state. Length is nStates*256.
	next []int32
	// out[state] lists the keyword ids that end at (or are suffixes of the path
	// to) state. Empty for almost every state, so the per-byte inner loop is a
	// no-op on the overwhelmingly common no-keyword text.
	out [][]int32
}

// buildAC compiles keywords into a dense Aho-Corasick DFA. Keyword id == index
// into the slice. Empty keywords are impossible in the gitleaks corpus and are
// ignored here; compileRules handles a rule that carried one by dropping its
// keyword gate entirely (see rules.go), which reproduces strings.Contains(x, "")
// == true without letting an empty pattern match at every position.
func buildAC(keywords []string) *acMatcher {
	// Phase 1: build the trie (the goto function) as sparse per-node maps. The
	// dense table is derived from it once the shape is known.
	type node struct {
		goto_ map[byte]int32
		fail  int32
		out   []int32
	}
	nodes := []*node{{goto_: map[byte]int32{}}} // node 0 is the root
	for id, kw := range keywords {
		if kw == "" {
			continue
		}
		cur := int32(0)
		for i := 0; i < len(kw); i++ {
			b := kw[i]
			nxt, ok := nodes[cur].goto_[b]
			if !ok {
				nxt = int32(len(nodes))
				nodes = append(nodes, &node{goto_: map[byte]int32{}})
				nodes[cur].goto_[b] = nxt
			}
			cur = nxt
		}
		nodes[cur].out = append(nodes[cur].out, int32(id))
	}

	// Phase 2: BFS from the root, computing failure links, folding failure-link
	// outputs into each node, and filling the dense transition table in the same
	// pass. Processing in BFS (increasing-depth) order guarantees that when a
	// node is visited its failure target -- always shallower -- is already final.
	n := len(nodes)
	m := &acMatcher{
		next: make([]int32, n*256),
		out:  make([][]int32, n),
	}
	queue := make([]int32, 0, n)
	for b := 0; b < 256; b++ {
		if u, ok := nodes[0].goto_[byte(b)]; ok {
			nodes[u].fail = 0
			m.next[b] = u // root row: 0<<8 | b == b
			queue = append(queue, u)
		} else {
			m.next[b] = 0 // missing root transition loops back to the root
		}
	}
	for len(queue) > 0 {
		r := queue[0]
		queue = queue[1:]
		for b := 0; b < 256; b++ {
			if u, ok := nodes[r].goto_[byte(b)]; ok {
				// The failure target of u is where the automaton goes on b from r's
				// own failure target -- already resolved in the dense table.
				nodes[u].fail = m.next[int(nodes[r].fail)<<8|b]
				if fo := nodes[nodes[u].fail].out; len(fo) > 0 {
					nodes[u].out = append(nodes[u].out, fo...)
				}
				m.next[int(r)<<8|b] = u
				queue = append(queue, u)
			} else {
				// No literal edge: inherit the failure target's transition.
				m.next[int(r)<<8|b] = m.next[int(nodes[r].fail)<<8|b]
			}
		}
	}
	for i, nd := range nodes {
		m.out[i] = nd.out
	}
	return m
}

// collect marks present[id] = true for every keyword id that occurs anywhere in
// lower (which the caller has already lowercased, so the automaton's lowercased
// keywords match with the same case semantics as the substring sweep did).
// present must be at least len(keywords) long; it is not reset here.
func (m *acMatcher) collect(lower string, present []bool) {
	st := int32(0)
	for i := 0; i < len(lower); i++ {
		st = m.next[int(st)<<8|int(lower[i])]
		for _, id := range m.out[st] {
			present[id] = true
		}
	}
}
