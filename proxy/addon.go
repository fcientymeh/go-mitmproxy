package proxy

import (
	"io"
	"net/http"

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
