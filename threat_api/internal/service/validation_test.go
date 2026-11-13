package service

import (
	"threat_api/internal/entity"
	"testing"
)

func TestIsValidMD5(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid lowercase",
			input: "d41d8cd98f00b204e9800998ecf8427e",
			want:  true,
		},
		{
			name:  "valid uppercase",
			input: "D41D8CD98F00B204E9800998ECF8427E",
			want:  true,
		},
		{
			name:  "too short",
			input: "d41d8cd98f00b204e9800998ecf8427",
			want:  false,
		},
		{
			name:  "invalid characters",
			input: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			want:  false,
		},
		{
			name:  "name with only spaces",
			input: "                                ",
			want:  false,
		},
		{
			name:  "empty string",
			input: "",
			want:  false,
		},
		{
			name:  "too long string",
			input: "d41d8cd98f00b204e9800998ecf8427e1",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidMD5(tt.input)

			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid normal name",
			input: "Valid Threat Name",
			want:  true,
		},
		{
			name:  "valid too short name",
			input: "a",
			want:  true,
		},
		{
			name:  "empty name",
			input: "",
			want:  false,
		},
		{
			name:  "name with only spaces",
			input: "   ",
			want:  false,
		},
		{
			name:  "name too long",
			input: string(make([]rune, 256)),
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateName(tt.input)
			got := err == nil
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateSeverity(t *testing.T) {
	tests := []struct {
		name  string
		input entity.Severity
		want  bool
	}{
		{
			name:  "valid low severity",
			input: entity.SeverityLow,
			want:  true,
		},
		{
			name:  "valid medium severity",
			input: entity.SeverityMedium,
			want:  true,
		},
		{
			name:  "valid high severity",
			input: entity.SeverityHigh,
			want:  true,
		},
		{
			name:  "valid critical severity",
			input: entity.SeverityCritical,
			want:  true,
		},
		{
			name:  "invalid severity",
			input: "invalid",
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateSeverity(tt.input)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
