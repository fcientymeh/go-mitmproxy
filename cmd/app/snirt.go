package main

import (
	"aisecproxy/proxy"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/coregx/coregex"
)

type RealtimeSWI struct {
	proxy.BaseAddon
	count int
}

// var titleRegexp = regexp.MustCompile("(<title>)(.*?)(</title>)")
// var titleRegexp = regexp.MustCompile("(<body>)(.*?)(</body>)")

// -- obrazek do podmiany dla blokowanych żądań
var blockedImage []byte

func init() {
	var err error
	blockedImage, err = os.ReadFile("blocked.jpg")
	if err != nil {
		panic(err)
	}
}

// -- tekst  do podmiany dla blokowanych żądań/stron
var body = []byte(`<title> AISECPROXY </title><body><h1>Site has been blocked</h1><p> 
					Access to this site is blocked for security reason.</p></body>`)

// -- testowe patterny regexp do szukania
var blockPatterns = []string{
	`(?i)cas{1,2}ino`,
	`(?i)hazard`,
	`(?i)malicious-domain\.com`,
	`(?i)free\s+crypto`,
}

func compilePatterns(patterns []string) []*coregex.Regexp {
	result := make([]*coregex.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		result = append(result, coregex.MustCompile(pattern))
	}
	return result
}

var compiledBlockPatterns = compilePatterns(blockPatterns)

func matchesBlockedContent(body []byte) (bool, string) {
	for _, re := range compiledBlockPatterns {
		if re.Match(body) {
			return true, re.String()
		}
	}
	return false, ""
}

// -- AIP hook na response content
func (a *RealtimeSWI) Response(f *proxy.Flow) {
	// analysis on response data
	if f.Response == nil {
		return
	}
	//contentType := f.Response.Header.Get("Content-Type")
	contentType := strings.Split(f.Response.Header.Get("Content-type"), ";")[0]
	// ext := proxy.MimeMap[contentType]
	//fmt.Println(ext)
	f.Response.ReplaceToDecodedBody() //rozpakowujemy wewnętrznie body http
	orgBodyContent := f.Response.Body

	// -- 1. tu można dorobić filtr na content-type
	// TODO: check-content type

	// -- Entry dla text regex
	if strings.Contains(strings.ToLower(contentType), "text/") {
		block, reason := analyseText(orgBodyContent)

		// blokujemy strone albo tylko ten zasób
		// jeśli tylko bedziemy modyfikować cos w tekscie - mozemy zjebać strony,
		// wieć najlepiej blokować tylko po body
		if block {
			sniBlockSite(f, reason)
		}

		return
	}

	// -- Entry dla images
	if strings.Contains(strings.ToLower(contentType), "image/jpeg") {
		block, reason := analyseImage(f, orgBodyContent)

		// blokujemy zasób (w sumie musi byc info że blocked)
		if block {
			sniBlockImage(f, reason)
		}
		return
	}

	//TODO: Entry dla po prostu blokowania po content type

	//sniBlockSite(f)
}

func analyseText(orgBodyContent []byte) (bool, string) {
	// black list
	// regexps
	blocked, pattern := matchesBlockedContent(orgBodyContent)
	return blocked, pattern
}

func analyseImage(f *proxy.Flow, orgBodyContent []byte) (bool, string) {
	// black list
	// regexps
	// smi policy
	blocked := true
	pattern := "Images forbidden"
	return blocked, pattern
}

func sniBlockSite(f *proxy.Flow, blockReason string) {
	// if !titleRegexp.Match(f.Response.Body) {
	// 	return
	// }
	body := []byte(fmt.Sprintf(
		`<html><head><title>AISECPROXY</title></head><body><h1>Site has been blocked</h1><p>Access to this site is blocked 
		for security reason: %s</p></body></html>`,
		blockReason,
	))
	f.Response.Body = body
	f.Response.Header.Set("Content-Length", strconv.Itoa(len(f.Response.Body)))
	f.Response.Header.Del("Content-Encoding")
}

func sniBlockText(f *proxy.Flow, blockReason string) { // TODO: blokowanie tekxtu, czyli replejsujemy tylko to co trzeba
	body := []byte(fmt.Sprintf(
		`<html><head><title>AISECPROXY</title></head><body><h1>Site has been blocked</h1><p>Access to this site is blocked 
		for security reason: %s</p></body></html>`,
		blockReason,
	))
	f.Response.Body = body
	f.Response.Header.Set("Content-Length", strconv.Itoa(len(f.Response.Body)))
	f.Response.Header.Del("Content-Encoding")
}

func sniBlockImage(f *proxy.Flow, blockReason string) {
	f.Response.Body = blockedImage
	f.Response.Header.Set("Content-Type", "image/jpeg")
	f.Response.Header.Set("Content-Length", strconv.Itoa(len(blockedImage)))
	f.Response.Header.Del("Content-Encoding")
	f.Response.Header.Del("Transfer-Encoding")
}
