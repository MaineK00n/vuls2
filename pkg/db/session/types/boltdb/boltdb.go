package boltdb

// ReservedRootBucket returns the set of top-level bucket names that are not
// ecosystems. A new slice is returned on each call so that callers cannot
// mutate shared state.
func ReservedRootBucket() []string {
	return []string{"datasource", "metadata", "microsoft", "vulnerability"}
}
