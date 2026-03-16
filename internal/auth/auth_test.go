package auth_test

import (
	"net/http"
	"testing"

	"github.com/JStephens72/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		want       string
		wantErr    bool
		errMessage string
	}{
		{
			name:       "no authorization header",
			headers:    http.Header{},
			want:       "",
			wantErr:    true,
			errMessage: auth.ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name: "malformed header - missing value",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			want:       "",
			wantErr:    true,
			errMessage: "malformed authorization header",
		},
		{
			name: "malformed header - wrong scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			want:       "",
			wantErr:    true,
			errMessage: "malformed authorization header",
		},
		{
			name: "valid API key",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			want:    "abc123",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := auth.GetAPIKey(tt.headers)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.errMessage != "" && err.Error() != tt.errMessage {
					t.Fatalf("expected error %q, got %q", tt.errMessage, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}
