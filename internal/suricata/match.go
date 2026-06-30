package suricata

import "slices"

// acAutomaton implements Aho-Corasick for multi-pattern matching.
// Build once at ruleset load time, then matchAll() runs in O(n) time
// where n is the length of the input data - regardless of rule count.
type acNode struct {
	children [256]*acNode // next byte in each of 256 possible values
	fail     *acNode      // failure link for automaton
	outputs  []int        // rule indices that end at this node
	depth    int
}

type acAutomaton struct {
	root  *acNode
	rules []*Rule
}

func newACAutomaton() *acAutomaton {
	return &acAutomaton{root: &acNode{}}
}

// build constructs the trie and builds failure links (BFS).
func (a *acAutomaton) build(rules []*Rule) {
	a.rules = rules
	a.root = &acNode{}

	for idx, rule := range rules {
		for _, cm := range rule.Contents {
			pattern := cm.Pattern
			if len(pattern) == 0 {
				continue
			}

			node := a.root
			for _, b := range pattern {
				next := node.children[b]
				if next == nil {
					next = &acNode{depth: node.depth + 1}
					node.children[b] = next
				}
				node = next
			}
			node.outputs = append(node.outputs, idx)
		}
	}

	// Build failure links via BFS.
	queue := make([]*acNode, 0)

	// Initialize depth-1 nodes (root's direct children).
	for i := 0; i < 256; i++ {
		child := a.root.children[i]
		if child != nil {
			child.fail = a.root
			queue = append(queue, child)
		} else {
			a.root.children[i] = a.root
		}
	}

	// BFS for remaining depths.
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		for i := 0; i < 256; i++ {
			child := node.children[i]
			if child == nil {
				node.children[i] = node.fail.children[i]
				continue
			}

			child.fail = node.fail.children[i]

			// Propagate outputs from failure node.
			if len(child.fail.outputs) > 0 {
				child.outputs = append(child.outputs, child.fail.outputs...)
			}

			queue = append(queue, child)
		}
	}
}

// matchAll runs the automaton against data and returns matching rule indices.
// O(n) where n = len(data), regardless of number of rules.
// Deduplicates: each rule index appears at most once in the result even if
// the pattern matches multiple times.
func (a *acAutomaton) matchAll(data []byte) []int {
	seen := make(map[int]struct{})
	node := a.root

	for _, b := range data {
		node = node.children[b]

		for _, idx := range node.outputs {
			seen[idx] = struct{}{}
		}
	}

	result := make([]int, 0, len(seen))
	for idx := range seen {
		result = append(result, idx)
	}

	// Sort for deterministic output.
	slices.Sort(result)
	return result
}
