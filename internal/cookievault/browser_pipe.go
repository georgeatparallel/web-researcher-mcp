package cookievault

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/cdp"
	"github.com/go-rod/rod/lib/launcher"
)

// pipeTransport carries DevTools messages over the two pipes Chrome reads and
// writes when started with --remote-debugging-pipe: JSON messages, each ended by
// a NUL byte. No TCP port is opened, so no other local process can reach the
// browser (issue #775). It satisfies cdp.WebSocketable.
type pipeTransport struct {
	out io.WriteCloser // browser stdin (fd 3 on unix)
	in  *bufio.Reader  // browser stdout (fd 4 on unix)
	mu  sync.Mutex
}

func (p *pipeTransport) Send(data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, err := p.out.Write(append(data[:len(data):len(data)], 0))
	return err
}

func (p *pipeTransport) Read() ([]byte, error) {
	msg, err := p.in.ReadBytes(0)
	if err != nil {
		return nil, err
	}
	return msg[:len(msg)-1], nil
}

// launchPipe starts the browser with a DevTools pipe instead of a TCP port. The
// browser exits by itself when the pipe closes, including when this process dies.
// The platform files supply configureChild, pipeFlags and killTree.
func launchPipe(o BrowserLaunch) (*ProfileBrowser, error) {
	bin := o.Bin
	if bin == "" {
		var err error
		if bin, err = launcher.NewBrowser().Get(); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrBrowserLaunch, err)
		}
	}

	toBrowserR, toBrowserW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBrowserLaunch, err)
	}
	fromBrowserR, fromBrowserW, err := os.Pipe()
	if err != nil {
		_ = toBrowserR.Close()
		_ = toBrowserW.Close()
		return nil, fmt.Errorf("%w: %w", ErrBrowserLaunch, err)
	}
	// The browser reads toBrowserR and writes fromBrowserW; the other two ends stay here.
	args := o.newLauncher().Delete("remote-debugging-port").Set("remote-debugging-pipe").FormatArgs()
	args = append(args, pipeFlags(toBrowserR, fromBrowserW)...)

	// bin is the configured or installed browser; args are fixed flags plus the
	// work dir this package created. Nothing here comes from a tool caller.
	// The browser outlives the launch call, so it gets no cancellable context;
	// Shutdown ends it.
	cmd := exec.CommandContext(context.Background(), bin, args...) // #nosec G204 -- see above
	configureChild(cmd, toBrowserR, fromBrowserW)
	startErr := cmd.Start()
	_ = toBrowserR.Close() // the child holds its own copies
	_ = fromBrowserW.Close()
	if startErr != nil {
		_ = toBrowserW.Close()
		_ = fromBrowserR.Close()
		return nil, fmt.Errorf("%w: %w", ErrBrowserLaunch, startErr)
	}
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()

	pb := &ProfileBrowser{pid: cmd.Process.Pid, exited: exited, kill: func() { killTree(cmd) }}
	pb.closePipes = func() { _ = toBrowserW.Close(); _ = fromBrowserR.Close() }

	client := cdp.New().Start(&pipeTransport{out: toBrowserW, in: bufio.NewReader(fromBrowserR)})
	br := rod.New().Client(client)
	if err := connectWithin(br, browserConnectWait); err != nil {
		pb.closePipes() // the browser exits when its pipe closes
		pb.Shutdown()
		return nil, fmt.Errorf("%w: %w", ErrBrowserLaunch, err)
	}
	pb.Browser = br
	return pb, nil
}

// connectWithin runs br.Connect and gives up after d, so a browser that starts
// but never answers cannot hold a lease or a browser slot.
func connectWithin(br *rod.Browser, d time.Duration) error {
	res := make(chan error, 1)
	go func() { res <- br.Connect() }()
	select {
	case err := <-res:
		return err
	case <-time.After(d):
		return errors.New("browser did not answer in time")
	}
}
