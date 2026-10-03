package tor

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

const (
	controlReadSize = 4096
	controlMaxLine  = 1024 * 1024
)

type Reply struct {
	Lines []string
	Code  int
}

type ControlError struct {
	Message string
	Code    int
}

type control struct {
	instance *nativeInstance
	buffer   []byte
	mutex    sync.Mutex
}

func (r Reply) Value(name string) (string, bool) {
	prefix := name + "="

	for _, line := range r.Lines {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix), true
		}
	}

	return "", false
}

func (err *ControlError) Error() string {
	if err.Message == "" {
		return fmt.Sprintf("Tor control error %d", err.Code)
	}

	return fmt.Sprintf("Tor control error %d: %s", err.Code, err.Message)
}

func (c *control) close() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.instance.closeControl()
}

func (c *control) command(ctx context.Context, command string) (Reply, error) {
	return c.commandBytes(ctx, []byte(command))
}

func (c *control) commandBytes(ctx context.Context, command []byte) (Reply, error) {
	if bytes.IndexAny(command, "\r\n") >= 0 {
		return Reply{}, fmt.Errorf("Tor control command contains a line break")
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	wire := make([]byte, 0, len(command)+2)

	wire = append(wire, command...)
	wire = append(wire, '\r', '\n')

	defer clear(wire)

	err := c.instance.write(ctx, wire)
	if err != nil {
		return Reply{}, err
	}

	for {
		reply, err := c.readReply(ctx)
		if err != nil {
			return Reply{}, err
		}

		// Events use 650. rotx does not subscribe to events, but consuming them
		// here makes the parser safe if Tor emits one around another command.
		if reply.Code == 650 {
			continue
		}

		if reply.Code >= 400 {
			message := ""
			if len(reply.Lines) != 0 {
				message = reply.Lines[len(reply.Lines)-1]
			}

			return reply, &ControlError{Code: reply.Code, Message: message}
		}

		return reply, nil
	}
}

func (c *control) readReply(ctx context.Context) (Reply, error) {
	var reply Reply

	for {
		line, err := c.readLine(ctx)
		if err != nil {
			return Reply{}, err
		}

		code, separator, text, err := parseControlLine(line)
		if err != nil {
			return Reply{}, err
		}

		if reply.Code == 0 {
			reply.Code = code
		} else if reply.Code != code {
			return Reply{}, fmt.Errorf("Tor control reply changed status from %d to %d", reply.Code, code)
		}

		reply.Lines = append(reply.Lines, text)

		if separator == '+' {
			err = c.readDataBlock(ctx)
			if err != nil {
				return Reply{}, err
			}
		}

		if separator == ' ' {
			return reply, nil
		}
	}
}

func (c *control) readDataBlock(ctx context.Context) error {
	for {
		line, err := c.readLine(ctx)
		if err != nil {
			return err
		}

		if line == "." {
			return nil
		}

		// Data blocks use SMTP-style dot stuffing. rotx currently discards their
		// contents, but consuming the complete block keeps the stream aligned.
	}
}

func (c *control) readLine(ctx context.Context) (string, error) {
	for {
		end := bytes.Index(c.buffer, []byte("\r\n"))
		if end >= 0 {
			line := string(c.buffer[:end])
			c.buffer = c.buffer[end+2:]

			return line, nil
		}

		if len(c.buffer) >= controlMaxLine {
			return "", fmt.Errorf("Tor control line exceeds %d bytes", controlMaxLine)
		}

		var incoming [controlReadSize]byte

		count, err := c.instance.read(ctx, incoming[:])
		if err != nil {
			return "", err
		}

		c.buffer = append(c.buffer, incoming[:count]...)
	}
}

func parseControlLine(line string) (int, byte, string, error) {
	if len(line) < 4 {
		return 0, 0, "", fmt.Errorf("malformed Tor control reply %q", line)
	}

	code, err := strconv.Atoi(line[:3])
	if err != nil || code < 100 || code > 699 {
		return 0, 0, "", fmt.Errorf("malformed Tor control status %q", line[:3])
	}

	separator := line[3]
	if separator != ' ' && separator != '-' && separator != '+' {
		return 0, 0, "", fmt.Errorf("malformed Tor control separator %q", separator)
	}

	return code, separator, line[4:], nil
}
