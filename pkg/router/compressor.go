package router

import (
	"compress/gzip"
	"fmt"
	"io"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/coalaura/rotx/pkg/config"
	"github.com/klauspost/compress/zstd"
)

type compressor struct {
	writer   compressionWriter
	encoding config.Encoding
}

// Fresh encoders allocate roughly 0.7–0.9 MiB per response in the encoder
// benchmark. Reuse preserves their working storage, with no retained response
// writers or source buffers; the GC can reclaim idle codecs under pressure.
var compressorPools [4]sync.Pool

func (encoder *compressor) Write(body []byte) (int, error) {
	return encoder.writer.Write(body)
}

func (encoder *compressor) Flush() error {
	return encoder.writer.Flush()
}

func (encoder *compressor) Reset(destination io.Writer) {
	switch writer := encoder.writer.(type) {
	case *gzip.Writer:
		writer.Reset(destination)
	case *zstd.Encoder:
		writer.Reset(destination)
	case *brotli.Writer:
		writer.Reset(destination)
	}
}

func (encoder *compressor) Close() error {
	err := encoder.writer.Close()

	encoder.Reset(io.Discard)

	compressorPools[encoder.encoding].Put(encoder)

	return err
}

func newCompressor(encoding config.Encoding, destination io.Writer) (*compressor, error) {
	if encoding < config.Zstd || encoding > config.Brotli {
		return nil, fmt.Errorf("unsupported compression encoding")
	}

	if cached, ok := compressorPools[encoding].Get().(*compressor); ok {
		cached.Reset(destination)

		return cached, nil
	}

	var (
		writer compressionWriter
		err    error
	)

	switch encoding {
	case config.Gzip:
		writer, err = gzip.NewWriterLevel(destination, gzip.BestSpeed)
	case config.Zstd:
		writer, err = zstd.NewWriter(destination, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(1<<20), zstd.WithZeroFrames(true))
	case config.Brotli:
		writer = brotli.NewWriterLevel(destination, 4)
	}

	if err != nil {
		return nil, err
	}

	return &compressor{writer: writer, encoding: encoding}, nil
}
