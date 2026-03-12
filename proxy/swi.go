package proxy

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"jaytaylor.com/html2text"

	//"github.com/go-redis/redis/v8"
	log "github.com/sirupsen/logrus"
)

func executeSwiMode(f *Flow) error {
	if f.Response != nil && len(f.Response.Header.Get("Content-type")) == 0 {
		// no content type in response, no dump
		return fmt.Errorf("No content type")
	}

	// Response body decoding
	respbodyArray, err := f.Response.DecodedBody()
	if err != nil {
		log.Error(err)
		return err
	}

	// Request body decoding
	reqbodyArray := f.Request.Body

	//Some checking...
	if (len(respbodyArray) <= *MinSizeDumpTextFile) && (f.Response.IsTextContentType()) {
		//fmt.Println("error 1")
		return nil
	}

	// Get content type and extension of object in response
	contentType := f.Response.Header.Get("Content-type")
	extens := MimeMap[strings.Split(contentType, ";")[0]]
	log.Debug("Content-type: ", contentType, ", extension: ", extens)

	// Dump response
	if extens != "" || *DumpAllFilesWithoutFiltering {
		swiDumpResponse(respbodyArray, f, contentType)
	}

	// Dump request
	if *Dumprequests { //(f.Request.Method != "GET") &&
		swiDumpRequest(f, reqbodyArray)
	}
	return nil
}

func swiDumpRequest(f *Flow, reqbodyArray []byte) error {
	// rozwalamy request na czesci i na pliki i podamy do PrepareJSONfileUpload
	// jesli content-type jest puste, to po prostu dumpujemy dane raw body, a jesli nie, to tam juz jest na 99 proc multipart
	// fmt.Print(string(f.Request.Body))
	if f.Request.Method == "GET" { //pustych samych żądań get nie chcemy
		return nil
	}
	contentType := f.Request.Header.Get("Content-Type")
	if !strings.Contains(contentType, "multipart/form-data") {
		//zrzucamy RAW, szybko i bezpolesnie, zakładamy prosty txt
		/*
			shaFile := sha256.Sum256(reqbodyArray)
			ttime := string(time.Now().Format("2006-01-02T15.04.05.00"))
			shaFileName := fmt.Sprintf("%x", shaFile) + ttime
		*/
		jsonFile, err := PrepareJSONfileTxt(f, 1, "text/plain", base64.StdEncoding.EncodeToString(reqbodyArray))
		if err != nil {
			log.Error(err)
			return err
		}

		ret := rclient.RPush(*RedisQueue, jsonFile)
		if ret.Err() != nil {
			log.Error(err)
			return err
		}

		return nil
	} // koniec obslugi reqesta prostego

	// poczatek obsługi multipartu
	// jesli jest multipart, jestesmy tutaj i niestety, bedzie troche roboty... (POST)
	// log.Println("jest multipart upload")
	formDataMultipartExist := strings.Split(contentType, "multipart/form-data; ")
	if len(formDataMultipartExist) < 1 {
		log.Error("Not supported to dump request header")
		return nil
	}

	splitBoundary := strings.Split(formDataMultipartExist[1], "boundary=")
	if len(splitBoundary) < 1 {
		log.Error("Multipart found, but no boundary info")
		return nil
	}

	boundaryID := strings.Split(formDataMultipartExist[1], "boundary=")[1]
	if len(boundaryID) == 0 {
		log.Error("Error in header, no boundary ID")
		return nil
	}
	boundaryBegin := "\r\n--" + boundaryID + "\r\n"
	boundaryEnd := "\r\n--" + boundaryID + "--"

	bbody := string(f.Request.Body)
	bbodyParsed := strings.Split(bbody, boundaryBegin)
	if len(bbodyParsed) == 0 {
		log.Error("Error parsing boundary in request")
		return nil
	}
	// log.Debugf("Boundary parsed")

	// fmt.Println(bbodyParsed) // tutaj mamy wlacznie z content type
	for i, _ := range bbodyParsed {
		tmpSplit := strings.Split(bbodyParsed[i], "\r\n\r\n")
		if len(tmpSplit) == 0 {
			log.Error("Error parsing boundary part in request")
			return nil
		}
		tmp := strings.Split(bbodyParsed[i], "\r\n\r\n")
		if len(tmp) < 2 {
			return nil
		}
		bbodyParsed[i] = tmp[1]
		tmpContentType := strings.Split(tmp[0], "\r\n")
		if len(tmpContentType) < 1 {
			return nil
		}
		// teraz lecimy po lewej stronie szukac contenet type
		var typeCT string
		for j, _ := range tmpContentType {
			//var cata string
			if strings.Contains(tmpContentType[j], "Content-Type") {
				typeCTtmp := strings.Split(tmpContentType[j], "Content-Type: ") //[1]
				if len(typeCTtmp) < 2 {
					//fmt.Print(string(f.Request.Body))
					return nil
				}
				typeCT = strings.Split(tmpContentType[j], "Content-Type: ")[1]
				//log.Debug("kontenet tajp jest")
				break
			}
		}
		if typeCT == "" {
			//fmt.Println("Kontent tajpa nie znaleziono. przypiszemy domyslny test/plain")
			typeCT = "text/plain"
		}

		if i == (len(bbodyParsed) - 1) { //sprawdzamy, czy to ostatni part
			tmpSplitEnd := strings.Split(bbodyParsed[len(bbodyParsed)-1], boundaryEnd)
			bbodyParsed[len(bbodyParsed)-1] = tmpSplitEnd[0]
			if len(tmpSplitEnd) == 0 {
				log.Error("Error parsing boundary at the end of request")
				return nil
			}
		}
		if (bbodyParsed[i]) == "" { //s ą requesty bez body, wiec bedziemy to olewac, niestety, dopiero tutaj to moge zrobic, po parsowaniu
			continue
		}
		/// jesli mime part to nie test*, zrzucamy plik na dysk
		// if !strings.Contains(typeCT, "text/") { //TODO: opisac w pliku konfiguracyjnym, ktore mime wysylamy razem z JSONem
		if MimeMapforJSON[typeCT] == 0 { //nie znaleziono, by mime zalaczyc do jsona, wiec zrzucamy przez dysk
			shaFile := sha256.Sum256([]byte(bbodyParsed[i]))
			//ttime := string(time.Now().Format("2006-01-02T15.04.05.00"))
			shaFileName := fmt.Sprintf("%x", shaFile) //+ ttime
			jsonFile, err := PrepareJSONfile(f, shaFileName, 1, typeCT)
			if err != nil {
				log.Error(err)
				continue // nie return'ujemy się, ale tylko konczymy iterację dla problematycznego content part'a
			}
			// Dump request
			err = AisecProxyDumpRequest(shaFileName, []byte(bbodyParsed[i]), f)
			if err != nil {
				//log.Println("blad przy zrzucie pliku proxydumpemrequesterem")
				continue
			}

			// Send event to redis
			ret := rclient.RPush(*RedisQueue, jsonFile)
			if ret.Err() != nil {
				log.Error(err)
				continue
			}
			// tutaj koniec petli for dla poszczegolnego parta
		} else {
			// opakowujemy do jsona, bo to text reqbodyArray))
			jsonFile, err := PrepareJSONfileTxt(f, 1, typeCT, base64.StdEncoding.EncodeToString([]byte(bbodyParsed[i])))
			if err != nil {
				log.Error(err)
				continue
			}
			// Send to redis
			ret := rclient.RPush(*RedisQueue, jsonFile)
			if ret.Err() != nil {
				log.Error(err)
				continue
			}
		}
	}
	return nil
}

func swiDumpResponse(respbodyArray []byte, f *Flow, contentType string) error {
	if !strings.Contains(contentType, "text/") {
		// MIME non-text - dump
		shaFile := sha256.Sum256(respbodyArray)
		// ttime := string(time.Now().Format("2006-01-02T15.04.05.00"))
		shaFileName := fmt.Sprintf("%x", shaFile) // + ttime

		// Generate JSON file for event
		jsonFile, err := PrepareJSONfile(f, shaFileName, 0, "")
		if err != nil {
			log.Error(err)
			return err
		}

		err = AisecProxyDumpResponse(shaFileName, respbodyArray, f)
		if err != nil {
			return err
		}
		// Push event to Redis
		ret := rclient.RPush(*RedisQueue, jsonFile)
		if ret.Err() != nil {
			fmt.Println(ret.Err().Error())
		}
		return nil
	} else {
		// MIME text formatted attach to JSON
		jsonFile, err := PrepareJSONfileTxt(f, 0, contentType, base64.StdEncoding.EncodeToString(respbodyArray))
		if err != nil {
			log.Error(err)
			return err
		}

		ret := rclient.RPush(*RedisQueue, jsonFile)
		if ret.Err() != nil {
			log.Error(err)
			return err

		}
		return nil // koniec obsługi dla mime nie textowych
	}
}

func AisecProxyDumpRequest(shaFileName string, bodyArray []byte, f *Flow) error {
	dirPrefix := shaFileName[:2]
	_, err := os.Stat(FilesStorage + "/" + dirPrefix)
	if os.IsNotExist(err) {
		log.Debug("Subdir does not exist. Will be created")
		_ = os.Mkdir(FilesStorage+"/"+dirPrefix, 0777)
	}
	// Check if request is dumped already
	proxyDumpedFilePath := FilesStorage + "/" + dirPrefix + "/" + shaFileName
	_, err = os.Stat(proxyDumpedFilePath)
	if os.IsExist(err) {
		log.Debug("File exists with the same sha256. Skipping dumping on filesystem")
		return nil
	}
	// Dump request on disk
	err = os.WriteFile(proxyDumpedFilePath, bodyArray, 0777)
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}

/*
AisecProxyDumpResponse dumps HTTP response body to disk using SHA256-based storage.
If enabled, HTML content is converted to plain text before dumping.
*/
func AisecProxyDumpResponse(shaFileName string, body []byte, f *Flow) error {
	dirPrefix := shaFileName[:2]
	dirPath := FilesStorage + "/" + dirPrefix

	// Ensure destination directory exists
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		log.Debug("Subdir does not exist, creating: " + dirPath)
		if err := os.Mkdir(dirPath, 0777); err != nil {
			return err
		}
	}

	filePath := dirPath + "/" + shaFileName

	// Skip if file already exists
	if _, err := os.Stat(filePath); err == nil {
		log.Debug("File with the same SHA256 already exists, skipping dump")
		return nil
	}

	contentType := strings.Split(f.Response.Header.Get("Content-type"), ";")[0]

	// Convert HTML to text if enabled
	if *ConvHtmlToTxtonDumping && contentType == "text/html" {
		text, err := html2text.FromString(
			string(body),
			html2text.Options{PrettyTables: false},
		)
		if err != nil {
			log.Debug("HTML to text conversion failed, dumping raw content")
			return os.WriteFile(filePath, body, 0777)
		}

		return os.WriteFile(filePath, []byte(text), 0777)
	}

	// Dump raw content
	return os.WriteFile(filePath, body, 0777)
}

/*
PrepareJSONfile prepares a JSON event without embedded text.
The attachment is dumped on disk to remain compatible with Suricata.
*/
func PrepareJSONfile(f *Flow, shaString string, directionInt int, typeCT string) ([]byte, error) {
	// directionInt: 0 = download, 1 = upload
	// Collect connection flow information to build the event payload.

	var (
		direction string
		CT        string
	)

	if directionInt == 0 {
		direction = "download"
		CT = strings.Split(f.Response.Header.Get("Content-type"), ";")[0]
	} else {
		direction = "upload"
		CT = typeCT
	}

	currentTime := time.Now()
	timeParam := currentTime.Format("2006-01-02T15:04:05.00-0700")
	flowParam := strconv.FormatInt(currentTime.UnixNano(), 5)

	// Server address
	sHost, sPort, err := net.SplitHostPort(f.ConnContext.ServerConn.Address)
	if err != nil {
		log.Error("Cannot get server IP, probably connection reset")
		return nil, err
	}

	sHostIP, _ := net.LookupIP(sHost) // TODO: get IP directly instead of DNS lookup
	if len(sHostIP) > 0 {
		sHost = sHostIP[0].String()
	} else {
		sHost = "0.0.0.0"
	}

	sPortInt, _ := strconv.Atoi(sPort)

	// Client address
	cHost, cPort, err := net.SplitHostPort(
		f.ConnContext.ClientConn.Conn.LocalAddr().String(),
	)
	if err != nil {
		log.Error("Cannot get client IP, probably connection reset")
		return nil, err
	}

	cPortInt, _ := strconv.Atoi(cPort)

	// aipayloadStructFileinfo metadata helper structure
	type aipayloadStructFileinfo struct {
		Filename string `json:"filename"`
		Sid      string `json:"sid"`
		Gaps     bool   `json:"gaps"`
		State    string `json:"state"`
		Sha256   string `json:"sha256"`
		Stored   bool   `json:"stored"`
		Size     int    `json:"size"`
		TxID     int    `json:"tx_id"`
	}

	// aipayloadStructHttp HTTP request data compatible with Suricata
	type aipayloadStructHttp struct {
		Hostname        string `json:"hostname"`
		URL             string `json:"url"`
		HTTPUserAgent   string `json:"http_user_agent"`
		HTTPContentType string `json:"http_content_type"`
		HTTPMethod      string `json:"http_method"`
		Protocol        string `json:"protocol"`
		Status          int    `json:"status"`
		Length          int64  `json:"length"`
	}

	// aipayloadStruct Event structure compatible with Suricata
	type aipayloadStruct struct {
		Timestamp string                  `json:"timestamp"`
		FlowID    string                  `json:"flow_id"`
		InIface   string                  `json:"in_iface"`
		EventType string                  `json:"event_type"`
		Direction string                  `json:"direction"`
		SrcIP     string                  `json:"src_ip"`
		SrcPort   int                     `json:"src_port"`
		DestIP    string                  `json:"dest_ip"`
		DestPort  int                     `json:"dest_port"`
		Proto     string                  `json:"proto"`
		HTTP      aipayloadStructHttp     `json:"http"`
		AppProto  string                  `json:"app_proto"`
		Fileinfo  aipayloadStructFileinfo `json:"fileinfo"`
	}

	payload := &aipayloadStruct{
		Timestamp: timeParam,
		FlowID:    flowParam,
		InIface:   "ens18",
		EventType: "fileinfo",
		Direction: direction,
		SrcIP:     cHost,
		SrcPort:   cPortInt,
		DestIP:    sHost,
		DestPort:  sPortInt,
		Proto:     "TCP",
		HTTP: aipayloadStructHttp{
			Hostname:        f.Request.raw.URL.Host,
			URL:             f.Request.raw.RequestURI,
			HTTPUserAgent:   f.Request.raw.UserAgent(),
			HTTPContentType: CT,
			HTTPMethod:      f.Request.Method,
			Protocol:        f.Request.Proto,
			Status:          f.Response.StatusCode,
			Length:          f.Request.raw.ContentLength,
		},
		AppProto: f.Request.raw.URL.Scheme,
		Fileinfo: aipayloadStructFileinfo{
			Filename: f.Request.raw.URL.Path,
			Sid:      "none",
			Gaps:     false,
			State:    "CLOSED",
			Sha256:   shaString,
			Stored:   true,
			Size:     len(f.Response.Body),
			TxID:     0,
		},
	}

	dataJSON, err := json.Marshal(payload)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return dataJSON, nil
}

/*
PrepareJSONfileTxt prepares a JSON payload with embedded text
for AI analysis based on HTTP flow data.
*/
func PrepareJSONfileTxt(f *Flow, directionInt int, typeCT string, body string) ([]byte, error) {
	// directionInt: 0 = download, 1 = upload
	// Some code is duplicated intentionally for simplicity.
	// The next maintainer will probably do it better :-)

	var (
		direction string
		CT        string
	)

	if directionInt == 0 {
		direction = "download"
		CT = strings.Split(f.Response.Header.Get("Content-type"), ";")[0]
	} else {
		direction = "upload"
		CT = typeCT
	}

	currentTime := time.Now()
	timeParam := currentTime.Format("2006-01-02T15:04:05.00-0700")
	flowParam := strconv.FormatInt(currentTime.UnixNano(), 5)

	// Server address
	sHost, sPort, err := net.SplitHostPort(f.ConnContext.ServerConn.Address)
	if err != nil {
		log.Error("Cannot get server IP, probably connection reset")
		return nil, err
	}

	sHostIP, _ := net.LookupIP(sHost) // TODO: get IP directly instead of DNS lookup
	if len(sHostIP) > 0 {
		sHost = sHostIP[0].String()
	} else {
		sHost = "0.0.0.0"
	}

	sPortInt, _ := strconv.Atoi(sPort)

	// Client address
	cHost, cPort, err := net.SplitHostPort(
		f.ConnContext.ClientConn.Conn.LocalAddr().String(),
	)
	if err != nil {
		log.Error("Cannot get client IP, probably connection reset")
		return nil, err
	}

	cPortInt, _ := strconv.Atoi(cPort)

	type alert struct {
		Action       string `json:"action"`
		Gid          int    `json:"gid"`
		SignatureID  int    `json:"signature_id"`
		Rev          int    `json:"rev"`
		FILEStoreAll string `json:"FILE store all"`
		Category     string `json:"category"`
		Severity     int    `json:"severity"`
	}

	type aipayloadStructHttp struct {
		Hostname         string `json:"hostname"`
		URL              string `json:"url"`
		HTTPUserAgent    string `json:"http_user_agent"`
		HTTPContentType  string `json:"http_content_type"`
		HTTPMethod       string `json:"http_method"`
		Protocol         string `json:"protocol"`
		Status           int    `json:"status"`
		Length           int64  `json:"length"`
		HTTPResponseBody string `json:"http_response_body"`
	}

	type aipayloadStruct struct {
		Timestamp string              `json:"timestamp"`
		FlowID    string              `json:"flow_id"`
		InIface   string              `json:"in_iface"`
		EventType string              `json:"event_type"`
		Direction string              `json:"direction"`
		SrcIP     string              `json:"src_ip"`
		SrcPort   int                 `json:"src_port"`
		DestIP    string              `json:"dest_ip"`
		DestPort  int                 `json:"dest_port"`
		Proto     string              `json:"proto"`
		HTTP      aipayloadStructHttp `json:"http"`
		AppProto  string              `json:"app_proto"`
		Alert     alert               `json:"alert"`
	}

	payload := &aipayloadStruct{
		Timestamp: timeParam,
		FlowID:    flowParam,
		InIface:   "ens18",
		EventType: "fileinfo",
		Direction: direction,
		SrcIP:     cHost,
		SrcPort:   cPortInt,
		DestIP:    sHost,
		DestPort:  sPortInt,
		Proto:     "TCP",
		HTTP: aipayloadStructHttp{
			Hostname:         f.Request.raw.URL.Host,
			URL:              f.Request.raw.RequestURI,
			HTTPUserAgent:    f.Request.raw.UserAgent(),
			HTTPContentType:  CT,
			HTTPMethod:       f.Request.Method,
			Protocol:         f.Request.Proto,
			Status:           f.Response.StatusCode,
			Length:           f.Request.raw.ContentLength,
			HTTPResponseBody: body,
		},
		AppProto: f.Request.raw.URL.Scheme,
		Alert: alert{
			Action:       "allowed",
			Gid:          1,
			SignatureID:  1,
			Rev:          1,
			FILEStoreAll: "FILE store all",
			Category:     "",
			Severity:     3,
		},
	}

	dataJSON, err := json.Marshal(payload)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return dataJSON, nil
}

/*
executeDumperMode executes dumper mode.
It only dumps files to disk without further processing.
*/
func executeDumperMode(f *Flow) error {
	contentType := strings.Split(f.Response.Header.Get("Content-type"), ";")[0]
	ext := MimeMap[contentType]

	body, _ := f.Response.DecodedBody()

	// Skip small text files
	if len(body) <= *MinSizeDumpTextFile && f.Response.IsTextContentType() {
		return nil
	}

	// Check if file should be dumped
	if ext == "" && !*DumpAllFilesWithoutFiltering {
		log.Debug("Extension " + contentType + " is not supported")
		return nil
	}

	timestamp := strconv.FormatInt(time.Now().UnixNano(), 5)
	savePath := FilesStorage + "/" + timestamp + ext

	// Convert HTML to text if enabled
	if *ConvHtmlToTxtonDumping && ext == ".html" {
		text, err := html2text.FromString(
			string(body),
			html2text.Options{PrettyTables: false},
		)
		if err != nil {
			log.Debug("Error converting HTML to plain text, dumping raw content")
			return os.WriteFile(savePath, body, 0777)
		}

		return os.WriteFile(savePath+".txt", []byte(text), 0777)
	}

	// Dump raw content
	return os.WriteFile(savePath, body, 0777)
}
