package models

import (
	"testing"
)

func TestRequestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  RequestConfig
		wantErr bool
	}{
		{
			name: "Valid GET",
			config: RequestConfig{
				Method: MethodGET,
				URL:    "http://example.com",
			},
			wantErr: false,
		},
		{
			name: "Valid POST",
			config: RequestConfig{
				Method:      MethodPOST,
				URL:         "http://example.com",
				Body:        "test",
				ContentType: ContentTypeForm,
			},
			wantErr: false,
		},
		{
			name: "Empty URL",
			config: RequestConfig{
				Method: MethodGET,
				URL:    "",
			},
			wantErr: true,
		},
		{
			name: "Invalid URL",
			config: RequestConfig{
				Method: MethodGET,
				URL:    "://invalid",
			},
			wantErr: true,
		},
		{
			name: "Invalid Method",
			config: RequestConfig{
				Method: "INVALID",
				URL:    "http://example.com",
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
