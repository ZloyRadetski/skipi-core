package geodata

// SKIPI patch (skipi-core/patches/xray-geodata): O(1) lookup of a geo entry.
//
// The upstream seek() walks the whole geo file for every geoip/geosite code, discarding the
// body of every other entry, so a rule set with N codes reads N times the file (73 MB for the
// RunetFreedom geosite). Here the entry table of a file (code -> offset, length) is built once
// with a few thousand small ReadAt calls and reused by every later lookup, also across core
// restarts. Readers without ReadAt/Stat (the Android asset fallback) keep the upstream scan.

import (
	"bufio"
	"encoding/binary"
	"io"
	"os"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

type skipiGeoSpan struct {
	off int64
	n   int
}

type skipiGeoIndex struct {
	size  int64
	mod   time.Time
	spans map[string]skipiGeoSpan
}

type skipiGeoFile interface {
	io.ReaderAt
	Stat() (os.FileInfo, error)
	Name() string
}

var skipiGeoIndexes = struct {
	sync.Mutex
	byPath map[string]*skipiGeoIndex
}{byPath: map[string]*skipiGeoIndex{}}

// skipiOpenEntry returns a reader positioned at the body of the entry for code and the body
// length: the replacement of "bufio.NewReaderSize + seek" in the upstream loader.
func skipiOpenEntry(r io.Reader, code []byte, size int64) (*bufio.Reader, int, error) {
	if f, ok := r.(skipiGeoFile); ok && len(code) > 0 {
		if span, found, err := skipiLookup(f, code); err == nil {
			if !found {
				return nil, 0, io.EOF // what the upstream scan reports for a missing code
			}
			body := io.NewSectionReader(f, span.off, int64(span.n))
			return bufio.NewReaderSize(body, 64*1024), span.n, nil
		}
		// An unreadable table is not final: the sequential scan below reports the real error.
	}
	br := bufio.NewReaderSize(r, 64*1024)
	n, err := seek(br, code, size)
	return br, n, err
}

func skipiLookup(f skipiGeoFile, code []byte) (skipiGeoSpan, bool, error) {
	info, err := f.Stat()
	if err != nil {
		return skipiGeoSpan{}, false, err
	}
	skipiGeoIndexes.Lock()
	defer skipiGeoIndexes.Unlock()
	idx := skipiGeoIndexes.byPath[f.Name()]
	if idx == nil || idx.size != info.Size() || !idx.mod.Equal(info.ModTime()) {
		spans, err := skipiBuildIndex(f, info.Size())
		if err != nil {
			return skipiGeoSpan{}, false, err
		}
		idx = &skipiGeoIndex{size: info.Size(), mod: info.ModTime(), spans: spans}
		skipiGeoIndexes.byPath[f.Name()] = idx
	}
	span, ok := idx.spans[string(code)]
	return span, ok, nil
}

// skipiBuildIndex walks the top-level entries of a geoip/geosite file reading only their headers.
// It accepts and rejects what seek() does: the first entry with a given code wins.
func skipiBuildIndex(f io.ReaderAt, size int64) (map[string]skipiGeoSpan, error) {
	spans := make(map[string]skipiGeoSpan, 512)
	var buf [128]byte
	for off := int64(0); off < size; {
		want := int64(len(buf))
		if size-off < want {
			want = size - off
		}
		n, err := f.ReadAt(buf[:want], off)
		if int64(n) < want {
			if err == nil || err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
		b := buf[:n]
		tag := b[0]
		x, vn := binary.Uvarint(b[1:])
		if vn <= 0 {
			return nil, errors.New("invalid body length in the geo file header")
		}
		if x == 0 || x > uint64(size) || x > uint64(^uint(0)>>1) {
			return nil, errors.New("invalid body length: ", x)
		}
		hdr := int64(1 + vn)
		bodyL := int64(x)
		if off+hdr+bodyL > size {
			return nil, io.ErrUnexpectedEOF
		}
		if tag == 0x0a && bodyL >= 2 && int64(len(b)) > hdr+1 && b[hdr] == 0x0a {
			if cl := int64(b[hdr+1]); cl > 0 && bodyL >= 2+cl {
				var code string
				if hdr+2+cl <= int64(len(b)) {
					code = string(b[hdr+2 : hdr+2+cl])
				} else {
					cb := make([]byte, cl)
					if _, err := f.ReadAt(cb, off+hdr+2); err != nil {
						return nil, err
					}
					code = string(cb)
				}
				if _, dup := spans[code]; !dup {
					spans[code] = skipiGeoSpan{off: off + hdr, n: int(bodyL)}
				}
			}
		}
		off += hdr + bodyL
	}
	return spans, nil
}
