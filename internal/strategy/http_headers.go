package strategy

const (
	headerAccept         = "Accept"
	headerAcceptEncoding = "Accept-Encoding"
	headerContentLength  = "Content-Length"
	encodingIdentity     = "identity"
)

// rangeAndConditionalHeaders are the request headers that make an origin
// response partial or conditional, and so unsafe to cache as a full body.
func rangeAndConditionalHeaders() []string {
	return []string{
		"If-Match",
		"If-Modified-Since",
		"If-None-Match",
		"If-Range",
		"If-Unmodified-Since",
		"Range",
	}
}
