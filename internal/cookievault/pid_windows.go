//go:build windows

package cookievault

// pidAlive always reports true on Windows, so leftover work folders fall back to
// the age rule in sweep.
func pidAlive(int) bool { return true }
