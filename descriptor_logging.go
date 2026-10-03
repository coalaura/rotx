package main

import (
	"github.com/coalaura/plain"
	"github.com/coalaura/rotx/pkg/tor"
)

type descriptorProgress struct {
	created   bool
	uploading bool
	published bool
}

func newDescriptorLogger(logger *plain.Plain, serviceCount int) func(tor.DescriptorEvent) {
	// Tor delivers descriptor events serially on its control reader.
	services := make(map[string]descriptorProgress, serviceCount)

	return func(event tor.DescriptorEvent) {
		progress := services[event.ServiceID]

		switch event.Action {
		case "CREATED":
			if !progress.created {
				logger.Infof("Descriptor created: %s.onion\n", event.ServiceID)

				progress.created = true
			}
		case "UPLOAD":
			if !progress.uploading {
				logger.Infof("Descriptor uploading: %s.onion\n", event.ServiceID)

				progress.uploading = true
			}
		case "UPLOADED":
			if !progress.published {
				logger.Infof("Descriptor published: %s.onion\n", event.ServiceID)

				progress.published = true
			}
		case "FAILED":
			reason := event.Reason
			if reason == "" {
				reason = "unspecified"
			}

			logger.Warnf("Descriptor upload failed: %s.onion: %s (HSDir %s)\n", event.ServiceID, reason, event.Directory)
		}

		services[event.ServiceID] = progress
	}
}
