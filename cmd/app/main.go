package main

import (
	"fmt"
	rawLog "log"
	"net/http"
	"os"
	"strings"

	"aisecproxy/addon"
	"aisecproxy/internal/helper"
	"aisecproxy/proxy"

	// "aisecproxy/web"

	"github.com/go-redis/redis"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	Version      bool     // show go-mitmproxy version
	Addr         string   // proxy listen addr
	WebAddr      string   // web interface listen addr
	SslInsecure  bool     // not verify upstream server SSL/TLS certificates.
	IgnoreHosts  []string // a list of ignore hosts
	AllowHosts   []string // a list of allow hosts
	CertPath     string   // path of generate cert files
	Debug        int      // debug mode: 1 - print debug log, 2 - show debug from
	Dump         string   // dump filename
	DumpLevel    int      // dump level: 0 - header, 1 - header + body
	Upstream     string   // upstream proxy
	UpstreamCert bool     // Connect to upstream server to look up certificate details. Default: True
	MapRemote    string   // map remote config filename
	MapLocal     string   // map local config filename
	LogFile      string   // log file path
	Filename     string   // read config from the filename
	ProxyAuth    string   // Require proxy authentication

	// fields needed for data investigation
	Loglevel                     int //not used at this time
	ProxyMode                    int
	StorageDir                   string
	RedisAddr                    string
	RedisPassword                string
	RedisDB                      int
	Redisqueuename               string
	MinSizeDumpTextFile          int
	Dumpallfileswithoutfiltering bool
	Dumprequests                 bool
	ConvHtmlToTxtonDumping       bool
}

func main() {
	fmt.Println("")
	fmt.Println("########## AIP HTTP(s) and Websocket proxy 2.0.1 ##########")
	fmt.Println("")
	fmt.Println(" ")

	config := loadConfig()
	fmt.Printf("%+v\n", config)
	fmt.Println(" ")

	log.Infof("Read MIME types from file")
	err := ReadMimeTypes()
	if err != nil {
		log.Println("Error reading mime configuration")
		os.Exit(-1)
	} else {
		log.Infof("Read MIME types from file read successfully")
	}

	log.Infof("Read MIME types in JSON from file")
	err = ReadMimeTypesInJSON()
	if err != nil {
		log.Println("Error reading mime for JSON")
		os.Exit(-1)
	} else {
		log.Infof("Read MIME types in JSON from file read successfully")
	}

	//TODO: read ignore hosts and allow hosts from big external database or something else

	if config.Debug > 0 {
		rawLog.SetFlags(rawLog.LstdFlags | rawLog.Lshortfile)
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	if config.Debug == 2 {
		log.SetReportCaller(true)
	}
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	opts := &proxy.Options{
		Debug:             config.Debug,
		Addr:              config.Addr,
		StreamLargeBodies: 1024 * 1024 * 5,
		SslInsecure:       config.SslInsecure,
		CaRootPath:        config.CertPath,
		Upstream:          config.Upstream,
		LogFilePath:       config.LogFile,
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		log.Fatal(err)
	}

	// AIS Initialize Redis client
	proxy.ClientRedis = redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})

	// AIS Set proxy globals
	proxy.ProxyWorkMode = &config.ProxyMode
	proxy.MinSizeDumpTextFile = &config.MinSizeDumpTextFile
	proxy.DumpAllFilesWithoutFiltering = &config.Dumpallfileswithoutfiltering
	proxy.ConvHtmlToTxtonDumping = &config.ConvHtmlToTxtonDumping
	proxy.FilesStorage = config.StorageDir
	proxy.RedisQueue = &config.Redisqueuename
	proxy.Dumprequests = &config.Dumprequests

	// Load IgnoreHosts interceptor - ignore hosts list from MITM attack
	if len(config.IgnoreHosts) > 0 {
		p.SetShouldInterceptRule(func(req *http.Request) bool {
			return !helper.MatchHost(req.Host, config.IgnoreHosts)
		})
	}

	// Load AllowHosts for filtering
	if len(config.AllowHosts) > 0 {
		p.SetShouldInterceptRule(func(req *http.Request) bool {
			return helper.MatchHost(req.Host, config.AllowHosts)
		})
	}

	if !config.UpstreamCert {
		p.AddAddon(proxy.NewUpstreamCertAddon(false))
		log.Infoln("UpstreamCert config false")
	}

	if config.ProxyAuth != "" && strings.ToLower(config.ProxyAuth) != "any" {
		log.Infoln("Enable entry authentication")
		auth := NewDefaultBasicAuth(config.ProxyAuth)
		p.SetAuthProxy(auth.EntryAuth)
	}

	if config.LogFile != "" {
		// Use instance logger with file output
		p.AddAddon(proxy.NewInstanceLogAddonWithFile(config.Addr, "", config.LogFile))
		log.Infof("Logging to file: %s", config.LogFile)
	} else {
		// Use default logger
		log.Infof("Logging to file disabled. Filename not set in configuration file.")
		p.AddAddon(&proxy.LogAddon{})
	}

	// p.AddAddon(web.NewWebAddon(config.WebAddr))

	if config.MapRemote != "" {
		mapRemote, err := addon.NewMapRemoteFromFile(config.MapRemote)
		if err != nil {
			log.Warnf("Load map remote error: %v", err)
		} else {
			p.AddAddon(mapRemote)
		}
	}

	if config.MapLocal != "" {
		mapLocal, err := addon.NewMapLocalFromFile(config.MapLocal)
		if err != nil {
			log.Warnf("Load map local error: %v", err)
		} else {
			p.AddAddon(mapLocal)
		}
	}

	if config.Dump != "" {
		dumper := addon.NewDumperWithFilename(config.Dump, config.DumpLevel)
		log.Infof("Logging requests dumps to file: %s", config.Dump)
		p.AddAddon(dumper)
	} else {
		log.Infof("Dumping requests headers to file disabled. Filename not set in configuration file.")
	}

	log.Fatal(p.Start())
}
