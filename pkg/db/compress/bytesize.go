package compress

import "fmt"

const (
	_ = 1 << (10 * iota)
	kib
	mib
	gib
)

func unit(size int64) string {
	switch {
	case size >= gib:
		return "GiB"
	case size >= mib:
		return "MiB"
	case size >= kib:
		return "KiB"
	default:
		return "B"
	}
}

func format(size int64, unit string) string {
	switch unit {
	case "GiB":
		return fmt.Sprintf("%.2f GiB", float64(size)/float64(gib))
	case "MiB":
		return fmt.Sprintf("%.2f MiB", float64(size)/float64(mib))
	case "KiB":
		return fmt.Sprintf("%.2f KiB", float64(size)/float64(kib))
	default:
		return fmt.Sprintf("%d B", size)
	}
}
