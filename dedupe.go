package main

// Direct port of deep_crawler.py's dedupe_with_locations. Python's version
// operates on dynamic dicts; Go's static typing means the equivalent here
// takes map[string]interface{} items (constructed by the two call sites in
// crawler.go -- sensitive findings and logic flaws) to preserve the exact
// same generic, reusable shape rather than writing two hand-duplicated
// dedup functions.

import (
	"encoding/json"
	"sort"
)

type DedupedEntry struct {
	Fields    map[string]interface{}
	Locations []interface{}
	SeenCount int
}

// canonicalize gives a stable string key for equality-checking a location
// value that might be a plain string or a small map (Python's dicts are
// naturally hashable-by-value for this purpose via tuple keys; Go needs an
// explicit canonical form since map/struct values aren't comparable the
// same way).
func canonicalize(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// DedupeWithLocations: collapse a list of finding maps that share the same
// identity (keyFields) into one entry with a Locations list, instead of one
// duplicate entry per occurrence. extraFields are informational fields
// whose first non-nil/non-"unknown" value wins across duplicates.
// locationFn extracts the per-occurrence location value from an item.
func DedupeWithLocations(items []map[string]interface{}, keyFields []string,
	extraFields []string, locationFn func(map[string]interface{}) interface{}) []DedupedEntry {

	type mergedEntry struct {
		fields       map[string]interface{}
		locations    []interface{}
		seenLocation map[string]bool
	}

	merged := make(map[string]*mergedEntry)
	var order []string

	for _, item := range items {
		keyParts := make([]interface{}, len(keyFields))
		for i, f := range keyFields {
			keyParts[i] = item[f]
		}
		key := canonicalize(keyParts)

		entry, exists := merged[key]
		if !exists {
			fields := make(map[string]interface{})
			for _, f := range keyFields {
				fields[f] = item[f]
			}
			for _, ef := range extraFields {
				fields[ef] = item[ef]
			}
			entry = &mergedEntry{fields: fields, seenLocation: make(map[string]bool)}
			merged[key] = entry
			order = append(order, key)
		} else {
			for _, ef := range extraFields {
				val := item[ef]
				existing := entry.fields[ef]
				if !isEmptyOrUnknown(val) && isEmptyOrUnknown(existing) {
					entry.fields[ef] = val
				}
			}
		}

		if locationFn != nil {
			loc := locationFn(item)
			if loc != nil {
				locKey := canonicalize(loc)
				if !entry.seenLocation[locKey] {
					entry.seenLocation[locKey] = true
					entry.locations = append(entry.locations, loc)
				}
			}
		}
	}

	result := make([]DedupedEntry, 0, len(order))
	for _, key := range order {
		e := merged[key]
		result = append(result, DedupedEntry{
			Fields:    e.fields,
			Locations: e.locations,
			SeenCount: len(e.locations),
		})
	}

	// Most-widespread first -- the same issue appearing across many
	// locations is usually more actionable to look at first. Stable sort
	// preserves first-seen order among ties, matching Python's
	// list.sort() stability.
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].SeenCount > result[j].SeenCount
	})

	return result
}

func isEmptyOrUnknown(v interface{}) bool {
	if v == nil {
		return true
	}
	if s, ok := v.(string); ok {
		return s == "" || s == "unknown"
	}
	return false
}
