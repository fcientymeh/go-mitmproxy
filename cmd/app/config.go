package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"aisecproxy/internal/helper"
	"aisecproxy/proxy"

	log "github.com/sirupsen/logrus"
)

func loadConfigFromFile(filename string) (*Config, error) {
	var config Config
	if err := helper.NewStructFromFile(filename, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func loadConfigFromCli() *Config {
	config := new(Config)

	flag.BoolVar(&config.Version, "version", false, "show go-mitmproxy version")
	flag.StringVar(&config.Addr, "addr", ":9080", "proxy listen addr")
	flag.StringVar(&config.WebAddr, "web_addr", ":9081", "web interface listen addr")
	flag.BoolVar(&config.SslInsecure, "ssl_insecure", true, "not verify upstream server SSL/TLS certificates.")
	flag.Var((*arrayValue)(&config.IgnoreHosts), "ignore_hosts", "a list of ignore hosts")
	flag.Var((*arrayValue)(&config.AllowHosts), "allow_hosts", "a list of allow hosts")
	flag.StringVar(&config.CertPath, "cert_path", "certs", "path of generate cert files")
	flag.IntVar(&config.Debug, "debug", 0, "debug mode: 1 - print debug log, 2 - show debug from")
	flag.StringVar(&config.Dump, "dump", "", "dump filename")
	flag.IntVar(&config.DumpLevel, "dump_level", 0, "dump level: 0 - header, 1 - header + body")
	flag.StringVar(&config.Upstream, "upstream", "", "upstream proxy")
	flag.BoolVar(&config.UpstreamCert, "upstream_cert", true, "connect to upstream server to look up certificate details")
	flag.StringVar(&config.MapRemote, "map_remote", "", "map remote config filename")
	flag.StringVar(&config.MapLocal, "map_local", "", "map local config filename")
	flag.StringVar(&config.LogFile, "log_file", "", "log file path")
	flag.StringVar(&config.Filename, "f", "", "read config from the filename")

	flag.IntVar(&config.MinSizeDumpTextFile, "minSizeDumpTextFile", 100, "minimum size (characters) to dump text/html file on disk")
	flag.BoolVar(&config.ConvHtmlToTxtonDumping, "convHtmlToTxtonDumping", false, "convert html body files to clean text")
	flag.BoolVar(&config.Dumpallfileswithoutfiltering, "dumpallfileswithoutfiltering", false, "dump all files without filtering by MIME")

	flag.IntVar(&config.ProxyMode, "proxymode", 0, "simple proxy: 0; 1 - swi dump JSON and files; 2 - decode and dump files only ")
	flag.StringVar(&config.StorageDir, "storage", "z:/suricata/", "path of storage files")
	flag.StringVar(&config.RedisAddr, "redisaddr", "wawcoremngm.fc.internal:6379", "redis address")
	flag.IntVar(&config.RedisDB, "redisdb", 0, "redis DB")
	flag.StringVar(&config.Redisqueuename, "redisqueuename", "aiplat", "redis queue name")
	flag.BoolVar(&config.Dumprequests, "dumprequests", false, "Dump requests and responses")
	flag.StringVar(&config.RedisPassword, "redisPassword", "", "redis password")
	flag.StringVar(&config.ProxyAuth, "proxyauth", "", `enable proxy authentication. Format: "username:pass", "user1:pass1|user2:pass2","any" to accept any user/pass combination`)
	flag.Parse()

	return config
}

func mergeConfigs(fileConfig, cliConfig *Config) *Config {
	config := new(Config)
	*config = *fileConfig
	if cliConfig.Addr != "" {
		config.Addr = cliConfig.Addr
	}
	if cliConfig.WebAddr != "" {
		config.WebAddr = cliConfig.WebAddr
	}
	if cliConfig.SslInsecure {
		config.SslInsecure = cliConfig.SslInsecure
	}
	if len(cliConfig.IgnoreHosts) > 0 {
		config.IgnoreHosts = cliConfig.IgnoreHosts
	}
	if len(cliConfig.AllowHosts) > 0 {
		config.AllowHosts = cliConfig.AllowHosts
	}
	if cliConfig.CertPath != "" {
		config.CertPath = cliConfig.CertPath
	}
	if cliConfig.Debug != 0 {
		config.Debug = cliConfig.Debug
	}
	if cliConfig.Dump != "" {
		config.Dump = cliConfig.Dump
	}
	if cliConfig.DumpLevel != 0 {
		config.DumpLevel = cliConfig.DumpLevel
	}
	if cliConfig.Upstream != "" {
		config.Upstream = cliConfig.Upstream
	}
	if !cliConfig.UpstreamCert {
		config.UpstreamCert = cliConfig.UpstreamCert
	}
	if cliConfig.MapRemote != "" {
		config.MapRemote = cliConfig.MapRemote
	}
	if cliConfig.MapLocal != "" {
		config.MapLocal = cliConfig.MapLocal
	}
	if cliConfig.LogFile != "" {
		config.LogFile = cliConfig.LogFile
	}

	return config
}

func loadConfig() *Config {
	log.Infof(("Loading config from file aisecproxy.json"))
	cliConfig := loadConfigFromCli()
	if cliConfig.Version {
		return cliConfig
	}

	var fileConfigExternal *Config
	if cliConfig.Filename == "" {
		fileConfig, err := loadConfigFromFile("aisecproxy.json")
		if err != nil {
			log.Warnf("read config from %v error %v", "aisecproxy.json", err)
			return cliConfig
		} else {
			fileConfigExternal = fileConfig
			log.Infof("Configuration from file read successfully")
			return fileConfigExternal
		}
	}

	return mergeConfigs(cliConfig, fileConfigExternal)
}

// arrayValue 实现了 flag.Value 接口
type arrayValue []string

func (a *arrayValue) String() string {
	return fmt.Sprint(*a)
}

func (a *arrayValue) Set(value string) error {
	*a = append(*a, value)
	return nil
}

// ReadMimeTypesInJSON reads MIME types from "mime_in_json.ini
func ReadMimeTypes() error {
	log.Println("Reading MIME configuration")

	file, err := os.Open("mime.ini")
	if err != nil {
		log.Fatal(err)
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			log.Warnf("Skipping invalid line: %q", line)
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		proxy.MimeMap[key] = value
		log.Info(key + "  " + value)
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

// ReadMimeTypesInJSON reads MIME types from "mime_in_json.ini"
// and populates proxy.MimeMapforJSON with sequential IDs.
// Desc: Suricata zrzuca texty bezposrednio do pliku JSON, ktorey leci do Redisa. Ale załaczniki na zewnatrz
// mime types_in_json definiuje, jakie mime typy mozemy zalaczyc od razu do JSONa, ktory leci do Redisa, a pozostałe muszą być
// zrzucone jako załączniki
func ReadMimeTypesInJSON() error {
	log.Println("Reading MIME types for JSON files sent to Redis")

	file, err := os.Open("mime_in_json.ini")
	if err != nil {
		log.Fatal(err)
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	idx := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue // skip empty lines
		}
		idx++
		proxy.MimeMapforJSON[line] = idx
	}

	// Check for scanning errors
	err = scanner.Err()
	if err != nil {
		return err
	}

	return nil
}
