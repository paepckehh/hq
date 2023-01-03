// package cubetoken
package cubetoken

// import
import (
	"os"
	"sync"
	"syscall"
)

//
// Display IO
//

// outSlice ...
func outSlice(msg []byte) {
	os.Stdout.Write(msg)
}

// global display engine
var displayChan, display = make(chan []byte, 15), sync.WaitGroup{}

// startDisplayEngine, a non-blocking conditional background output handler
func startDisplayEngine(c *Config) {
	if c.Progress {
		if getColorUI(c) {
			go func() {
				outSlice([]byte(_blue))
				for b := range displayChan {
					outSlice(b)
				}
				outSlice([]byte(_off))
				display.Done()
			}()
			return
		}
		go func() {
			outSlice([]byte(_blue))
			for b := range displayChan {
				outSlice(b)
			}
			outSlice([]byte(_off))
			display.Done()
		}()
		return

	}
	display.Done()
}

//
// Display IO Color UI
//

// const
const (
	// env
	_envNoColor = "NO_COLOR"
	// basic ansi terminal color definitions
	_off  = "\033[0m"
	_blue = "\033[2;34m"
)

// getColorUI ...
func getColorUI(c *Config) bool {
	if c.ForceNoColor {
		return false
	}
	if _, ok := syscall.Getenv(_envNoColor); ok {
		return false
	}
	return true
}
