//go:build windows

package cookievault

import "errors"

// pipeSupported is false on Windows: the DevTools pipe needs inherited file
// descriptors, so the browser keeps a loopback debug port there.
const pipeSupported = false

func launchPipe(BrowserLaunch) (*ProfileBrowser, error) {
	return nil, errors.New("devtools pipe is not available on windows")
}
