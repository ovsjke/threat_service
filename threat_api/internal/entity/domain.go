package entity

import (
	"errors"
	"time"
)

var (
	ErrThreatNotFound      = errors.New("threat not found")
	ErrThreatAlreadyExists = errors.New("threat already exists")
	ErrInvalidMD5          = errors.New("invalid md5 value")
	ErrInvalidSeverity     = errors.New("invalid severity value")
	ErrInvalidName         = errors.New("invalid name value")
	ErrNameTooLong         = errors.New("name value is too long")
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Threat struct {
	MD5         string
	Name        string
	Description string
	Severity    Severity
	DetectedAt  time.Time
	UpdatedAt   time.Time
}
