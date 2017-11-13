package whois

import (
	"fmt"
	"io/ioutil"
	"net"
	"regexp"
	"strings"
)

func queryServer(server string, domain string) (string, error) {
	connection, err := net.Dial("tcp", server+":43")
	if err != nil {
		return "", err
	}

	defer connection.Close()

	connection.Write([]byte(domain + "\r\n"))

	buffer, err := ioutil.ReadAll(connection)
	if err != nil {
		return "", err
	}

	return string(buffer[:]), nil
}

var serverRegexp, _ = regexp.Compile(`(?im)^.*whois.*:\s*[a-z0-9\-\.]+\s*$`)
var domainRegexp, _ = regexp.Compile(`(?im)^.*domain.*:.*$`)

func findServer(record string) string {
	line := serverRegexp.FindString(record)
	fields := strings.Fields(line)
	if len(fields) > 0 {
		return fields[len(fields)-1]
	}
	return ""
}

func findTld(record string) string {
	line := domainRegexp.FindString(record)
	fields := strings.Fields(line)
	if len(fields) > 0 {
		return strings.ToLower(fields[len(fields)-1])
	}
	return ""
}

func getRegistryServer(domain string) (string, error) {
	record, err := queryServer("whois.iana.org", domain)
	if err != nil {
		return "", err
	}

	server := findServer(record)
	if len(server) > 0 {
		return server, nil
	}

	tld := findTld(record)
	if len(tld) == 0 {
		return "", fmt.Errorf("Whois server for %s not found", domain)
	}

	server = "whois.nic." + tld

	_, err = queryServer(server, "nic."+tld)
	if err != nil {
		return "", fmt.Errorf("Whois server for %s not found", domain)
	}

	return server, nil
}

func isThinRegistry(server string) bool {
	if server == "whois.verisign-grs.com" {
		return true
	}
	return false
}

func GetWhois(domain string) (string, error) {
	registryServer, err := getRegistryServer(domain)
	if err != nil {
		return "", err
	}

	registryRecord, err := queryServer(registryServer, domain)
	if err != nil {
		return "", err
	}

	if !isThinRegistry(registryServer) {
		return registryRecord, nil
	}

	registrarServer := findServer(registryRecord)

	if len(registrarServer) == 0 {
		return registryRecord, nil
	}

	registrarRecord, err := queryServer(registrarServer, domain)
	if err != nil {
		return "", err
	}

	return registryRecord + registrarRecord, nil
}
