package router

import (
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/coalaura/rotx/pkg/config"
)

func (r *Router) serveRepresentation(response *Response, request *http.Request, root *os.Root, name string, file *os.File, info fs.FileInfo) error {
	policy := response.route.Compression()
	if policy.Count == 0 {
		return serveFile(response, request, file, info)
	}

	varyEncoding(response.Header())

	if noTransform(request.Header) {
		policy.Count = 0
	}

	encoding, acceptable := negotiateEncoding(request.Header.Values("Accept-Encoding"), policy)
	if !acceptable {
		return writeStatus(response, request, http.StatusNotAcceptable, "Not Acceptable\n")
	}

	if encoding == config.IdentityEncoding {
		return serveFile(response, request, file, info)
	}

	err := setSourceType(response.Header(), file, info.Name())
	if err != nil {
		return err
	}

	companion, companionInfo, err := openRegular(root, name+encoding.Suffix())
	if err != nil && encoding == config.Zstd {
		companion, companionInfo, err = openRegular(root, name+".zstd")
	}

	if err == nil {
		defer companion.Close()

		tag := `W/"` + strconv.FormatInt(companionInfo.ModTime().UnixNano(), 16) + "-" + strconv.FormatInt(companionInfo.Size(), 16) + "-" + encoding.String() + `"`

		metadata := Metadata{
			Modified: companionInfo.ModTime(),
			Size:     companionInfo.Size(),
			ETag:     tag,
		}

		return serveEncoded(response, request, info.Name(), companion, metadata, encoding)
	}

	key := compressionKey{Path: filepath.Join(root.Name(), name), Encoding: encoding}

	content, err := r.compression.content(request.Context(), file, info, key, policy.Cache)
	if err != nil {
		return err
	}

	defer content.close()

	tag := `"` + content.hash + "-" + encoding.String() + `-1"`

	metadata := Metadata{
		Modified: info.ModTime(),
		Size:     content.size,
		ETag:     tag,
	}

	return serveEncoded(response, request, info.Name(), content.reader, metadata, encoding)
}

func serveEncoded(response *Response, request *http.Request, name string, content io.ReadSeeker, metadata Metadata, encoding config.Encoding) error {
	err := response.SetMetadata(metadata)
	if err != nil {
		return err
	}

	response.Header().Set("Content-Encoding", encoding.String())
	response.Header().Set("Content-Length", strconv.FormatInt(metadata.Size, 10))
	response.Header().Set("Etag", metadata.ETag)

	request = contentRequest(request)

	// ServeContent's multipart envelope is not encoded, so retaining the selected
	// Content-Encoding would mislabel it. HTTP permits ignoring a Range request;
	// return the complete representation rather than an invalid encoded envelope.
	if strings.Contains(request.Header.Get("Range"), ",") {
		request = request.Clone(request.Context())

		request.Header.Del("Range")
	}

	// Ranges refer to bytes of this selected encoded representation. Seekable
	// content also gives HEAD and preconditions the same metadata as GET.
	http.ServeContent(response, request, name, metadata.Modified, content)

	return response.err
}

func setSourceType(headers http.Header, file *os.File, name string) error {
	media := mime.TypeByExtension(filepath.Ext(name))
	if media == "" {
		var prefix [512]byte

		count, err := file.ReadAt(prefix[:], 0)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}

		media = http.DetectContentType(prefix[:count])
	}

	headers.Set("Content-Type", media)

	return nil
}

func contentRequest(request *http.Request) *http.Request {
	if values, present := request.Header["If-None-Match"]; present && (len(values) != 1 || values[0] == "") {
		request = request.Clone(request.Context())

		request.Header.Set("If-None-Match", strings.Join(values, ", "))
		request.Header.Del("If-Modified-Since")
	}

	return request
}
