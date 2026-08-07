package restless

import "strings"

// HAR 1.2 envelope construction. Implements CONTRACT.md section 7.

type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type PostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type HarContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type HarRequest struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []NameValue `json:"headers"`
	QueryString []NameValue `json:"queryString"`
	PostData    *PostData   `json:"postData,omitempty"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

type HarResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []NameValue `json:"headers"`
	Content     HarContent  `json:"content"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
}

type HarTimings struct {
	Send    int `json:"send"`
	Wait    int `json:"wait"`
	Receive int `json:"receive"`
}

type HarEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            int         `json:"time"`
	Request         HarRequest  `json:"request"`
	Response        HarResponse `json:"response"`
	Timings         HarTimings  `json:"timings"`
}

// CapturedRequest is the framework-agnostic shape every adapter produces.
//
// Body fields are pointers so that "no body captured" (nil) stays distinct
// from "empty body" (""): HAR-011 reports -1 for the first and 0 for the
// second, and a plain string could not tell them apart.
type CapturedRequest struct {
	RequestID    string
	StartedAt    string
	Duration     int
	RoutePattern string

	Method         string
	URL            string
	RequestHeaders map[string]string
	RequestBody    *string

	Status          int
	ResponseHeaders map[string]string
	ResponseBody    *string

	User             *UserContext
	ErrorFingerprint *Fingerprint
	StackTrace       string

	// headerOrder preserves the order headers were captured in (HAR-004).
	// Go maps have deliberately randomized iteration order, so without this
	// the same request would serialize its headers differently every time.
	requestHeaderOrder  []string
	responseHeaderOrder []string
}

func headersToList(headers map[string]string, order []string) []NameValue {
	out := make([]NameValue, 0, len(headers))
	seen := make(map[string]bool, len(headers))
	for _, name := range order {
		if value, ok := headers[name]; ok && !seen[name] {
			out = append(out, NameValue{Name: name, Value: value})
			seen[name] = true
		}
	}
	// Anything not in the recorded order (or when no order was recorded) is
	// appended in sorted order, so the output is at least deterministic.
	if len(out) < len(headers) {
		rest := make([]string, 0, len(headers)-len(out))
		for name := range headers {
			if !seen[name] {
				rest = append(rest, name)
			}
		}
		sortStrings(rest)
		for _, name := range rest {
			out = append(out, NameValue{Name: name, Value: headers[name]})
		}
	}
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ParseQueryString parses the query into ordered name/value pairs (HAR-005).
//
// Hand-rolled rather than net/url.ParseQuery, which returns a map and so
// loses both order and duplicate names.
func ParseQueryString(rawURL string) []NameValue {
	out := []NameValue{}
	q := strings.Index(rawURL, "?")
	if q == -1 {
		return out
	}
	rest := rawURL[q+1:]
	if hash := strings.Index(rest, "#"); hash != -1 {
		rest = rest[:hash]
	}
	if rest == "" {
		return out
	}
	for _, pair := range strings.Split(rest, "&") {
		if pair == "" {
			continue
		}
		if eq := strings.Index(pair, "="); eq == -1 {
			out = append(out, NameValue{Name: percentDecode(pair), Value: ""})
		} else {
			out = append(out, NameValue{
				Name:  percentDecode(pair[:eq]),
				Value: percentDecode(pair[eq+1:]),
			})
		}
	}
	return out
}

// ToHarEntry builds the HAR entry for one captured request/response pair.
func ToHarEntry(c CapturedRequest) HarEntry {
	reqContentType := c.RequestHeaders["content-type"]
	resContentType := c.ResponseHeaders["content-type"]
	if resContentType == "" {
		resContentType = "application/octet-stream" // HAR-007
	}

	request := HarRequest{
		Method:      c.Method,
		URL:         c.URL,
		HTTPVersion: "HTTP/1.1", // HAR-003
		Headers:     headersToList(c.RequestHeaders, c.requestHeaderOrder),
		QueryString: ParseQueryString(c.URL),
		HeadersSize: -1, // HAR-012
		BodySize:    -1, // HAR-011
	}
	if c.RequestBody != nil {
		// HAR-010: UTF-8 BYTES, not len() and not code points.
		request.BodySize = utf8Len(*c.RequestBody)
		if *c.RequestBody != "" {
			// HAR-006: postData only when a body was actually captured.
			request.PostData = &PostData{MimeType: reqContentType, Text: *c.RequestBody}
		}
	}

	response := HarResponse{
		Status:      c.Status,
		StatusText:  "", // HAR-008
		HTTPVersion: "HTTP/1.1",
		Headers:     headersToList(c.ResponseHeaders, c.responseHeaderOrder),
		Content:     HarContent{Size: 0, MimeType: resContentType, Text: ""},
		HeadersSize: -1,
		BodySize:    -1,
	}
	if c.ResponseBody != nil {
		response.Content.Size = utf8Len(*c.ResponseBody)
		response.Content.Text = *c.ResponseBody
		response.BodySize = utf8Len(*c.ResponseBody)
	}

	return HarEntry{
		StartedDateTime: c.StartedAt, // HAR-001
		Time:            c.Duration,
		Request:         request,
		Response:        response,
		Timings:         HarTimings{Send: 0, Wait: c.Duration, Receive: 0}, // HAR-002
	}
}
