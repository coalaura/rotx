package tor

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	expandedEd25519PrivateKeySize = 64
	defaultOnionCloseTimeout      = 5 * time.Second
)

type Service struct {
	ID         string
	Target     string
	PrivateKey []byte
	ClientKeys []string
	Port       uint16
	PoW        bool
}

type Onion struct {
	instance *Instance
	ID       string

	closeOnce sync.Once
	closeErr  error
}

func (instance *Instance) AddOnion(ctx context.Context, service Service) (*Onion, error) {
	err := validateService(service)
	if err != nil {
		return nil, err
	}

	if service.PoW && !Versions().PoW {
		return nil, fmt.Errorf("embedded Tor lacks proof-of-work support")
	}

	encodedLength := base64.StdEncoding.EncodedLen(len(service.PrivateKey))
	command := make([]byte, 0, encodedLength+len(service.Target)+128+len(service.ClientKeys)*66)

	command = appendOnionCommand(command, service)

	defer clear(command)

	reply, err := instance.control.commandBytes(ctx, command)
	if err != nil {
		return nil, err
	}

	serviceID, ok := reply.Value("ServiceID")
	if !ok {
		return nil, fmt.Errorf("tor ADD_ONION reply did not contain ServiceID")
	}

	if serviceID != service.ID {
		return nil, fmt.Errorf("tor registered onion %q, expected %q", serviceID, service.ID)
	}

	return &Onion{instance: instance, ID: serviceID}, nil
}

func (onion *Onion) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultOnionCloseTimeout)
	defer cancel()

	return onion.CloseContext(ctx)
}

func (onion *Onion) CloseContext(ctx context.Context) error {
	onion.closeOnce.Do(func() {
		_, onion.closeErr = onion.instance.control.command(ctx, "DEL_ONION "+onion.ID)
	})

	return onion.closeErr
}

func validateService(service Service) error {
	for _, key := range service.ClientKeys {
		if len(key) != 52 || strings.Trim(key, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != "" {
			return fmt.Errorf("client authorization requires a base32 X25519 public key")
		}
	}

	if len(service.ID) != 56 || strings.Trim(service.ID, "abcdefghijklmnopqrstuvwxyz234567") != "" {
		return fmt.Errorf("onion service ID must be a lowercase 56-character v3 onion name without .onion")
	}

	if len(service.PrivateKey) != expandedEd25519PrivateKeySize {
		return fmt.Errorf("onion private key must contain %d expanded Ed25519 bytes", expandedEd25519PrivateKeySize)
	}

	if service.Port == 0 {
		return fmt.Errorf("onion virtual port must be non-zero")
	}

	host, port, err := net.SplitHostPort(service.Target)
	if err != nil {
		return fmt.Errorf("parse onion target: %w", err)
	}

	address := net.ParseIP(host)
	if address == nil || !address.IsLoopback() {
		return fmt.Errorf("onion target must use a numeric loopback address")
	}

	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return fmt.Errorf("onion target must use a non-zero TCP port")
	}

	return nil
}

func appendOnionCommand(command []byte, service Service) []byte {
	command = append(command, "ADD_ONION ED25519-V3:"...)
	command = base64.StdEncoding.AppendEncode(command, service.PrivateKey)
	command = append(command, " Port="...)
	command = strconv.AppendUint(command, uint64(service.Port), 10)
	command = append(command, ',')
	command = append(command, service.Target...)
	command = append(command, " PoWDefensesEnabled="...)

	if service.PoW {
		command = append(command, '1')
	} else {
		command = append(command, '0')
	}

	if len(service.ClientKeys) > 0 {
		command = append(command, " Flags=V3Auth"...)

		for _, key := range service.ClientKeys {
			command = append(command, " ClientAuthV3="...)
			command = append(command, key...)
		}
	}

	return command
}
