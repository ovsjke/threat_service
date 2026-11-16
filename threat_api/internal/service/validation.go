package service

import (
	"github.com/ovsjke/threat_service/threat_api/internal/entity"
	"regexp"
	"strings"
	"unicode/utf8"
)

var hex32Regex = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

func IsValidMD5(s string) bool {
	return hex32Regex.MatchString(s)
}

func ValidateName(name string) error {
	if name == "" || strings.TrimSpace(name) == "" {
		return entity.ErrInvalidName
	}
	if utf8.RuneCountInString(name) > 255 {
		return entity.ErrNameTooLong
	}
	return nil
}

func ValidateSeverity(severity entity.Severity) bool {
	switch severity {
	case entity.SeverityLow, entity.SeverityMedium, entity.SeverityHigh, entity.SeverityCritical:
		return true
	default:
		return false
	}
}
