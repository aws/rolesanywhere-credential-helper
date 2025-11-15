package aws_signing_helper

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetupHandlers(t *testing.T) {
	roleName := "roleName"

	mockPutTokenHandler := func(w http.ResponseWriter, r *http.Request) {}
	mockGetRoleNameHandler := func(w http.ResponseWriter, r *http.Request) {}
	mockGetCredentialsHandler := func(w http.ResponseWriter, r *http.Request) {}

	handler := setupHandlers(roleName, mockPutTokenHandler, mockGetRoleNameHandler, mockGetCredentialsHandler)
	server := httptest.NewServer(handler)
	defer server.Close()

	testCases := []struct {
		name   string
		path   string
		method string
	}{
		{"PutTokenHandler without trailing slash", TOKEN_RESOURCE_PATH, "PUT"},
		{"PutTokenHandler with trailing slash", TOKEN_RESOURCE_PATH_WITH_TRAILING_SLASH, "PUT"},
		{"GetRoleNameHandler without trailing slash", SECURITY_CREDENTIALS_RESOURCE_PATH, "GET"},
		{"GetRoleNameHandler with trailing slash", SECURITY_CREDENTIALS_RESOURCE_PATH_WITH_TRAILING_SLASH, "GET"},
		{"GetCredentialsHandler without trailing slash", SECURITY_CREDENTIALS_RESOURCE_PATH_WITH_TRAILING_SLASH + roleName, "GET"},
		{"GetCredentialsHandler with trailing slash", SECURITY_CREDENTIALS_RESOURCE_PATH_WITH_TRAILING_SLASH + roleName + "/", "GET"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, server.URL+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			client := &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if status := resp.StatusCode; status != http.StatusOK {
				t.Errorf("handler for %s returned wrong status code: got %v want %v", tc.path, status, http.StatusOK)
			}
		})
	}
}