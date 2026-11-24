package helps

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
)

// HTTPWebsocketCompatibility includes all effective handshake headers and the
// endpoint/proxy. Only CPA's generated fallback ID is connection-owned; explicit
// IDs always partition the pool. Secrets are hashed, never logged.
func HTTPWebsocketCompatibility(endpoint, proxyURL string, headers http.Header, generatedSession string, compression bool, callerScope ...string) string {
	h := sha256.New()
	add := func(v string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(v)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(v))
	}
	add(endpoint)
	add(proxyURL)
	scope := ""
	if len(callerScope) > 0 {
		scope = callerScope[0]
	}
	add(scope)
	if compression {
		add("compression")
	} else {
		add("no-compression")
	}
	canonical := make(map[string][]string, len(headers))
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		values := headers[name]
		name = strings.ToLower(name)
		if name == "session_id" && generatedSession != "" && len(values) == 1 && values[0] == generatedSession {
			continue
		}
		canonical[name] = append(canonical[name], values...)
	}
	keys := make([]string, 0, len(canonical))
	for name := range canonical {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		add(name)
		add(stringHTTPWebsocketKeyLength(len(canonical[name])))
		for _, value := range canonical[name] {
			add(value)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func stringHTTPWebsocketKeyLength(n int) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	return string(b[:])
}
