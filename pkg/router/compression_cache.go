package router

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/coalaura/rotx/pkg/config"
)

const compressionCacheDirectory = "data/cache/compress"

type sourceStamp struct {
	Size     int64
	Modified int64
}

type compressionKey struct {
	Path     string
	Encoding config.Encoding
}

type memoryEntry struct {
	previous *memoryEntry
	next     *memoryEntry
	key      compressionKey
	stamp    sourceStamp
	data     []byte
	hash     string
}

type compressionRecord struct {
	Stamp   sourceStamp
	Hash    string
	Version int
}

type compressedContent struct {
	reader io.ReadSeeker
	file   *os.File
	remove string
	hash   string
	size   int64
}

type compressionCache struct {
	mutex sync.Mutex
	// Stripes bound coordination memory independently of the number of sources.
	stripes   [64]sync.Mutex
	entries   map[compressionKey]*memoryEntry
	newest    *memoryEntry
	oldest    *memoryEntry
	limit     int64
	used      int64
	directory string
}

func (content *compressedContent) close() {
	if content.file != nil {
		content.file.Close()
	}

	if content.remove != "" {
		os.Remove(content.remove)
	}
}

func (cache *compressionCache) get(key compressionKey, stamp sourceStamp) *memoryEntry {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	entry := cache.entries[key]
	if entry == nil {
		return nil
	}

	cache.unlink(entry)

	if entry.stamp != stamp {
		delete(cache.entries, key)
		cache.used -= int64(len(entry.data))

		return nil
	}

	cache.linkNewest(entry)

	return entry
}

func (cache *compressionCache) put(key compressionKey, stamp sourceStamp, data []byte, hash string) {
	if int64(len(data)) > cache.limit {
		return
	}

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	if cache.entries == nil {
		cache.entries = make(map[compressionKey]*memoryEntry)
	}

	previous := cache.entries[key]
	if previous != nil {
		cache.unlink(previous)

		cache.used -= int64(len(previous.data))
	}

	for cache.oldest != nil && cache.used+int64(len(data)) > cache.limit {
		entry := cache.oldest

		cache.unlink(entry)
		delete(cache.entries, entry.key)

		cache.used -= int64(len(entry.data))
	}

	// Retain only compressed bytes, never spare bytes.Buffer capacity. Readers
	// hold immutable slices and remain valid after eviction.
	entry := &memoryEntry{key: key, stamp: stamp, data: bytes.Clone(data), hash: hash}

	cache.entries[key] = entry
	cache.used += int64(len(entry.data))

	cache.linkNewest(entry)
}

func (cache *compressionCache) unlink(entry *memoryEntry) {
	if entry.previous != nil {
		entry.previous.next = entry.next
	} else {
		cache.oldest = entry.next
	}

	if entry.next != nil {
		entry.next.previous = entry.previous
	} else {
		cache.newest = entry.previous
	}
}

func (cache *compressionCache) linkNewest(entry *memoryEntry) {
	entry.previous = cache.newest
	entry.next = nil

	if cache.newest != nil {
		cache.newest.next = entry
	} else {
		cache.oldest = entry
	}

	cache.newest = entry
}

func (cache *compressionCache) content(ctx context.Context, source *os.File, info fs.FileInfo, key compressionKey, mode config.CompressionCache) (*compressedContent, error) {
	stamp := sourceStamp{Size: info.Size(), Modified: info.ModTime().UnixNano()}

	if mode == config.CompressCacheMemory {
		entry := cache.get(key, stamp)
		if entry != nil {
			return memoryContent(entry.data, entry.hash), nil
		}
	}

	digest := sha256.Sum256([]byte(key.Path))

	if mode != config.CompressCacheOff {
		stripe := &cache.stripes[digest[0]%byte(len(cache.stripes))]

		stripe.Lock()
		defer stripe.Unlock()
	}

	if mode == config.CompressCacheMemory {
		entry := cache.get(key, stamp)
		if entry != nil {
			return memoryContent(entry.data, entry.hash), nil
		}

		var buffer bytes.Buffer

		hash, err := compressSource(ctx, &buffer, source, info, key.Encoding)
		if err != nil {
			return nil, err
		}

		cache.put(key, stamp, buffer.Bytes(), hash)

		return memoryContent(buffer.Bytes(), hash), nil
	}

	var (
		directory  string
		recordPath string
	)

	if mode == config.CompressCacheFile {
		directory = cache.directory
		recordPath = filepath.Join(directory, hex.EncodeToString(digest[:])+".json")

		record, err := readCompressionRecord(recordPath)
		if err == nil && record.Stamp == stamp {
			content, openError := openCompressed(filepath.Join(directory, record.Hash+key.Encoding.Suffix()), record.Hash)
			if openError == nil {
				return content, nil
			}
		}

		err = os.MkdirAll(directory, 0o700)
		if err != nil {
			return nil, err
		}
	}

	file, err := os.CreateTemp(directory, ".compress-*")
	if err != nil {
		return nil, err
	}

	content := &compressedContent{reader: file, file: file, remove: file.Name()}

	var success bool

	defer func() {
		if !success {
			content.close()
		}
	}()

	content.hash, err = compressSource(ctx, file, source, info, key.Encoding)
	if err != nil {
		return nil, err
	}

	content.size, err = file.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	if mode == config.CompressCacheFile {
		err = file.Sync()
		if err != nil {
			return nil, err
		}

		err = file.Close()
		if err != nil {
			return nil, err
		}

		path := filepath.Join(directory, content.hash+key.Encoding.Suffix())

		err = publishCompressed(content.remove, path)
		if err != nil {
			return nil, err
		}

		content.remove = ""

		record := compressionRecord{Stamp: stamp, Hash: content.hash, Version: 1}

		err = writeCompressionRecord(recordPath, record)
		if err != nil {
			return nil, err
		}

		return openCompressed(path, content.hash)
	}

	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	success = true

	return content, nil
}

func memoryContent(data []byte, hash string) *compressedContent {
	return &compressedContent{reader: bytes.NewReader(data), size: int64(len(data)), hash: hash}
}

func openCompressed(path, hash string) (*compressedContent, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()

		return nil, fmt.Errorf("invalid compressed cache file %q", path)
	}

	return &compressedContent{reader: file, file: file, size: info.Size(), hash: hash}, nil
}

func compressSource(ctx context.Context, destination io.Writer, source *os.File, info fs.FileInfo, encoding config.Encoding) (string, error) {
	encoder, err := newCompressor(encoding, destination)
	if err != nil {
		return "", err
	}

	checksum := sha256.New()

	var buffer [32 * 1024]byte

	for {
		err = ctx.Err()
		if err != nil {
			break
		}

		count, readError := source.Read(buffer[:])
		if count > 0 {
			checksum.Write(buffer[:count])

			_, err = encoder.Write(buffer[:count])
			if err != nil {
				break
			}
		}

		if readError != nil {
			if !errors.Is(readError, io.EOF) {
				err = readError
			}

			break
		}
	}

	err = errors.Join(err, encoder.Close())
	if err != nil {
		return "", err
	}

	after, err := source.Stat()
	if err != nil {
		return "", err
	}

	if after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return "", fmt.Errorf("source changed during compression")
	}

	var digest [sha256.Size]byte

	return hex.EncodeToString(checksum.Sum(digest[:0])), nil
}

func readCompressionRecord(path string) (compressionRecord, error) {
	var record compressionRecord

	contents, err := os.ReadFile(path)
	if err != nil {
		return record, err
	}

	err = json.Unmarshal(contents, &record)
	if err != nil {
		return record, err
	}

	if record.Version != 1 || len(record.Hash) != 64 {
		return record, fmt.Errorf("invalid compression cache record")
	}

	for _, digit := range record.Hash {
		if digit < '0' || digit > '9' && digit < 'a' || digit > 'f' {
			return record, fmt.Errorf("invalid compression cache hash")
		}
	}

	return record, nil
}

func writeCompressionRecord(path string, record compressionRecord) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".index-*")
	if err != nil {
		return err
	}

	defer os.Remove(file.Name())
	defer file.Close()

	err = json.NewEncoder(file).Encode(record)
	if err != nil {
		return err
	}

	err = file.Sync()
	if err != nil {
		return err
	}

	err = file.Close()
	if err != nil {
		return err
	}

	return os.Rename(file.Name(), path)
}

func publishCompressed(temporary, destination string) error {
	err := os.Rename(temporary, destination)
	if err == nil {
		return nil
	}

	// Windows may refuse replacement while another request has the same
	// content-addressed representation open. Its bytes are interchangeable.
	info, statError := os.Stat(destination)
	if statError == nil && info.Mode().IsRegular() {
		return os.Remove(temporary)
	}

	return err
}
