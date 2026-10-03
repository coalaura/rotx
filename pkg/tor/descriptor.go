package tor

import "strings"

// DescriptorEvent reports Tor's HS_DESC progress. UPLOADED confirms acceptance
// by one directory, not client reachability or completion of every replica.
type DescriptorEvent struct {
	Action    string
	ServiceID string
	Directory string
	Reason    string
}

func descriptorHandler(handler func(DescriptorEvent)) func(Reply) {
	return func(reply Reply) {
		for _, line := range reply.Lines {
			event, ok := parseDescriptorEvent(line)
			if ok {
				handler(event)
			}
		}
	}
}

func parseDescriptorEvent(line string) (DescriptorEvent, bool) {
	var (
		event    DescriptorEvent
		position int
	)

	for field := range strings.FieldsSeq(line) {
		switch position {
		case 0:
			if field != "HS_DESC" {
				return DescriptorEvent{}, false
			}
		case 1:
			event.Action = field
		case 2:
			event.ServiceID = field
		case 4:
			event.Directory = field
		default:
			reason, found := strings.CutPrefix(field, "REASON=")
			if found {
				event.Reason = reason
			}
		}

		position++
	}

	if position < 5 || len(event.ServiceID) != 56 || strings.Trim(event.ServiceID, "abcdefghijklmnopqrstuvwxyz234567") != "" {
		return DescriptorEvent{}, false
	}

	switch event.Action {
	case "CREATED", "UPLOAD", "UPLOADED", "FAILED":
		return event, true
	default:
		return DescriptorEvent{}, false
	}
}
