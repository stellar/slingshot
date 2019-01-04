package bc

import "time"

// Millis converts a time.Time to a number of milliseconds since 1970.
func Millis(t time.Time) uint64 {
	return uint64(t.UnixNano()) / uint64(time.Millisecond)
}

// FromMillis converts a number of milliseconds since 1970 to a time.Time.
func FromMillis(ms uint64) time.Time {
	return time.Unix(0, int64(ms*uint64(time.Millisecond))).UTC()
}

// DurationMillis converts a time.Duration to a number of milliseconds.
func DurationMillis(d time.Duration) uint64 {
	return uint64(d / time.Millisecond)
}

// MillisDuration coverts milliseconds to a time.Duration.
func MillisDuration(m uint64) time.Duration {
	return time.Duration(m) * time.Millisecond
}
