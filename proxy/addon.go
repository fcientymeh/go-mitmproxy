package proxy

import (
	"io"
	"net/http"
	"time"

	"github.com/go-redis/redis"
	log "github.com/sirupsen/logrus"
)

type Addon interface {
	// A client has connected to mitmproxy. Note that a connection can correspond to multiple HTTP requests.
	ClientConnected(*ClientConn)

	// A client connection has been closed (either by us or the client).
	ClientDisconnected(*ClientConn)

	// Mitmproxy has connected to a server.
	ServerConnected(*ConnContext)

	// A server connection has been closed (either by us or the server).
	ServerDisconnected(*ConnContext)

	// The TLS handshake with the server has been completed successfully.
	TlsEstablishedServer(*ConnContext)

	// HTTP request headers were successfully read. At this point, the body is empty.
	Requestheaders(*Flow)

	// The full HTTP request has been read.
	Request(*Flow)

	// HTTP response headers were successfully read. At this point, the body is empty.
	Responseheaders(*Flow)

	// The full HTTP response has been read.
	Response(*Flow)

	// Stream request body modifier
	StreamRequestModifier(*Flow, io.Reader) io.Reader

	// Stream response body modifier
	StreamResponseModifier(*Flow, io.Reader) io.Reader

	// onAccessProxyServer
	AccessProxyServer(req *http.Request, res http.ResponseWriter)

	WebSocketStart(*Flow)
	WebSocketMessage(*Flow)
	WebSocketEnd(*Flow)

	// Server-Sent Events hooks
	// SSE stream started (detected text/event-stream content type)
	SSEStart(*Flow)
	// Each SSE event received (access via f.SSE.Events[len(f.SSE.Events)-1])
	SSEMessage(*Flow)
	// SSE stream ended
	SSEEnd(*Flow)

	// HTTP request failed with error
	RequestError(*Flow, error)

	// HTTP CONNECT request failed with error
	HTTPConnectError(*Flow, error)
}

// BaseAddon do nothing
type BaseAddon struct{}

func (addon *BaseAddon) ClientConnected(*ClientConn)                                  {}
func (addon *BaseAddon) ClientDisconnected(*ClientConn)                               {}
func (addon *BaseAddon) ServerConnected(*ConnContext)                                 {}
func (addon *BaseAddon) ServerDisconnected(*ConnContext)                              {}
func (addon *BaseAddon) TlsEstablishedServer(*ConnContext)                            {}
func (addon *BaseAddon) Requestheaders(*Flow)                                         {}
func (addon *BaseAddon) Request(*Flow)                                                {}
func (addon *BaseAddon) Responseheaders(*Flow)                                        {}
func (addon *BaseAddon) Response(*Flow)                                               {}
func (addon *BaseAddon) StreamRequestModifier(f *Flow, in io.Reader) io.Reader        { return in }
func (addon *BaseAddon) StreamResponseModifier(f *Flow, in io.Reader) io.Reader       { return in }
func (addon *BaseAddon) AccessProxyServer(req *http.Request, res http.ResponseWriter) {}
func (addon *BaseAddon) WebSocketStart(*Flow)                                         {}
func (addon *BaseAddon) WebSocketMessage(*Flow)                                       {}
func (addon *BaseAddon) WebSocketEnd(*Flow)                                           {}
func (addon *BaseAddon) SSEStart(*Flow)                                               {}
func (addon *BaseAddon) SSEMessage(*Flow)                                             {}
func (addon *BaseAddon) SSEEnd(*Flow)                                                 {}
func (addon *BaseAddon) RequestError(*Flow, error)                                    {}
func (addon *BaseAddon) HTTPConnectError(*Flow, error)                                {}

// AM Aiseclab
// hashmap MIME types
var MimeMap = make(map[string]string)
var MimeMapforJSON = make(map[string]int)
var FilesStorage string //will be injected from main.go
var ProxyWorkMode *int
var MinSizeDumpTextFile *int
var DumpAllFilesWithoutFiltering *bool
var ConvHtmlToTxtonDumping *bool
var Dumprequests *bool
var ClientRedis *redis.Client
var RedisQueue *string
var rclient = redis.NewClient(&redis.Options{
	Addr:     "wawcoremngm.fc.internal:6379", //TODO - read from config
	Password: "",
	DB:       0,
})

// LogAddon log connection and flow
type LogAddon struct {
	BaseAddon
}

func (addon *LogAddon) ClientConnected(client *ClientConn) {
	log.Debugf("%v client connect\n", client.Conn.RemoteAddr())
}

func (addon *LogAddon) ClientDisconnected(client *ClientConn) {
	log.Debugf("%v client disconnect\n", client.Conn.RemoteAddr())
}

func (addon *LogAddon) ServerConnected(connCtx *ConnContext) {
	log.Debugf("%v server connect %v (%v->%v)\n", connCtx.ClientConn.Conn.RemoteAddr(), connCtx.ServerConn.Address, connCtx.ServerConn.Conn.LocalAddr(), connCtx.ServerConn.Conn.RemoteAddr())
}

func (addon *LogAddon) ServerDisconnected(connCtx *ConnContext) {
	log.Debugf("%v server disconnect %v (%v->%v) - %v\n", connCtx.ClientConn.Conn.RemoteAddr(), connCtx.ServerConn.Address, connCtx.ServerConn.Conn.LocalAddr(), connCtx.ServerConn.Conn.RemoteAddr(), connCtx.FlowCount.Load())
}

// Logika dla SWI
func (addon *LogAddon) Requestheaders(f *Flow) {
	go func() {
		<-f.Done()
		if f.Response == nil || f.Response.Body == nil {
			log.Debug("No headers or body in stream")
			return
		}

		switch *ProxyWorkMode {
		case 0: // klasyczne proxy, ale nic nie zrzuca, nie analizuje
		case 1:
			// tryb analizy z SWI
			//funkcja zwraca error, ale nie jest obsługiwany, bo w sumie do niczego go nie potrzbujemy. Albo dump się uda, albo nie
			// wszelkie logowanie jest w trakcie. decelowo usupełni się może na potrzebę statystyk
			// log.Debug("Executing swi mode for request")
			go executeSwiMode(f)
		case 2:
			// tryb  dumpera wykrytych MIME typów na filestore
			//funkcja zwraca error, ale nie jest obsługiwany, bo w sumie do niczego go nie potrzbujemy. Albo dump się uda, albo nie
			// wszelkie logowanie jest w trakcie
			go executeDumperMode(f)
		default:
			return
		}
	}()
	log.Debugf("%v Requestheaders %v %v\n", f.ConnContext.ClientConn.Conn.RemoteAddr(), f.Request.Method, f.Request.URL.String())
}

func (addon *LogAddon) Response(f *Flow) {
	var StatusCode int
	if f.Response != nil {
		StatusCode = f.Response.StatusCode
	}
	var contentLen int
	if f.Response != nil && f.Response.Body != nil {
		contentLen = len(f.Response.Body)
	}
	log.Infof("%v %v %v %v %v - %v ms\n", f.ConnContext.ClientConn.Conn.RemoteAddr(), f.Request.Method, f.Request.URL.String(), StatusCode, contentLen, time.Since(f.StartTime).Milliseconds())
}

func (addon *LogAddon) RequestError(f *Flow, err error) {
	var StatusCode int
	if f.Response != nil {
		StatusCode = f.Response.StatusCode
	}
	log.Errorf("%v %v %v %v - ERROR: %v - %v ms\n", f.ConnContext.ClientConn.Conn.RemoteAddr(), f.Request.Method, f.Request.URL.String(), StatusCode, err, time.Since(f.StartTime).Milliseconds())
}

func (addon *LogAddon) HTTPConnectError(f *Flow, err error) {
	log.Errorf("%v CONNECT ERROR %v - %v\n", f.ConnContext.ClientConn.Conn.RemoteAddr(), f.Request.URL.Host, err)
}

// WebSocketStart 记录 WebSocket 连接建立
func (addon *LogAddon) WebSocketStart(f *Flow) {
	log.Infof("%v WebSocket START %s - %s\n",
		f.ConnContext.ClientConn.Conn.RemoteAddr(),
		f.Request.URL.String(),
		f.ConnContext.ServerConn.Address)
}

// WebSocketMessage 记录 WebSocket 消息
func (addon *LogAddon) WebSocketMessage(f *Flow) {
	lastMsg := f.WebScoket.Messages[len(f.WebScoket.Messages)-1]
	direction := "C->S"
	if !lastMsg.FromClient {
		direction = "S->C"
	}
	msgType := "TEXT"
	if lastMsg.Type == 2 {
		msgType = "BINARY"
	}

	// 只记录消息长度，不记录内容
	log.Infof("%v WebSocket MSG %s %s [%s] len=%d\n",
		f.ConnContext.ClientConn.Conn.RemoteAddr(),
		f.Request.URL.String(),
		direction,
		msgType,
		len(lastMsg.Content))
}

// WebSocketEnd 记录 WebSocket 连接结束
func (addon *LogAddon) WebSocketEnd(f *Flow) {
	log.Infof("%v WebSocket END %s - %d messages\n",
		f.ConnContext.ClientConn.Conn.RemoteAddr(),
		f.Request.URL.String(),
		len(f.WebScoket.Messages))
}

// SSEStart 记录 SSE 流开始
func (addon *LogAddon) SSEStart(f *Flow) {
	log.Infof("%v SSE START %s - %s\n",
		f.ConnContext.ClientConn.Conn.RemoteAddr(),
		f.Request.URL.String(),
		f.ConnContext.ServerConn.Address)
}

// SSEMessage 记录 SSE 事件
func (addon *LogAddon) SSEMessage(f *Flow) {
	// 获取最新的 SSE 事件
	events := f.SSE.Events
	if len(events) == 0 {
		return
	}
	event := events[len(events)-1]

	// 只记录事件长度，不记录内容
	log.Infof("%v SSE EVENT %s [%s] id=%s data_len=%d\n",
		f.ConnContext.ClientConn.Conn.RemoteAddr(),
		f.Request.URL.String(),
		event.Event,
		event.ID,
		len(event.Data))
}

// SSEEnd 记录 SSE 流结束
func (addon *LogAddon) SSEEnd(f *Flow) {
	var StatusCode int
	if f.Response != nil {
		StatusCode = f.Response.StatusCode
	}
	eventCount := 0
	if f.SSE != nil {
		eventCount = len(f.SSE.Events)
	}

	// 记录格式与 Response 保持一致，但标注为 SSE
	log.Infof("%v %v %v %v %d [SSE] - %v ms\n",
		f.ConnContext.ClientConn.Conn.RemoteAddr(),
		f.Request.Method,
		f.Request.URL.String(),
		StatusCode,
		eventCount,
		time.Since(f.StartTime).Milliseconds())
}

type UpstreamCertAddon struct {
	BaseAddon
	UpstreamCert bool // Connect to upstream server to look up certificate details.
}

func NewUpstreamCertAddon(upstreamCert bool) *UpstreamCertAddon {
	return &UpstreamCertAddon{UpstreamCert: upstreamCert}
}

func (addon *UpstreamCertAddon) ClientConnected(conn *ClientConn) {
	conn.UpstreamCert = addon.UpstreamCert
}
