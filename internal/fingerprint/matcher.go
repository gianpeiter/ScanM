package fingerprint

import "strings"

func IdentifyService(banner string) string {
	b := strings.ToLower(banner)
	
	switch {
	case strings.Contains(b, "ssh-2.0-openssh"):
		return "OpenSSH"
	case strings.Contains(b, "nginx"):
		return "Nginx"
	case strings.Contains(b, "apache"):
		return "Apache HTTPD"
	case strings.Contains(b, "microhttpd"):
		return "CCTV/IoT Camera"
	case strings.Contains(b, "mysql"):
		return "MySQL Database"
	default:
		return "Unknown Service"
	}
}