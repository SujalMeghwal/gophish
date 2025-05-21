package controllers

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
)

// attemptLogin handles the login POST flow including fetching a fresh CSRF token.
func attemptLogin(t *testing.T, ctx *testContext, client *http.Client, username, password, optionalPath string) *http.Response {
	t.Helper()

	loginURL := fmt.Sprintf("%s/login", ctx.adminServer.URL)
	
	// Step 1: GET login page to fetch CSRF token and cookie
	resp, err := http.Get(loginURL)
	if err != nil {
		t.Fatalf("error requesting the /login endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("invalid status code received from /login page. expected %d got %d", http.StatusOK, resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatalf("error parsing /login response body: %v", err)
	}

	token, exists := doc.Find("input[name='csrf_token']").Attr("value")
	if !exists {
		t.Fatal("unable to find csrf_token value in login response")
	}

	if client == nil {
		client = &http.Client{}
	}

	// Step 2: POST login credentials with CSRF token and cookies
	formData := url.Values{
		"username":   {username},
		"password":   {password},
		"csrf_token": {token},
	}

	req, err := http.NewRequest("POST", loginURL+optionalPath, strings.NewReader(formData.Encode()))
	if err != nil {
		t.Fatalf("error creating POST /login request: %v", err)
	}

	// Pass the Set-Cookie from the GET to the POST request
	if cookie := resp.Header.Get("Set-Cookie"); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("error sending POST /login request: %v", err)
	}

	return resp
}

// TestLoginCSRF verifies that login POST without CSRF token is forbidden.
func TestLoginCSRF(t *testing.T) {
	ctx := setupTest(t)
	defer tearDown(t, ctx)

	resp, err := http.PostForm(fmt.Sprintf("%s/login", ctx.adminServer.URL),
		url.Values{
			"username": {"admin"},
			"password": {"gophish"},
		})

	if err != nil {
		t.Fatalf("error sending POST /login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status %d but got %d", http.StatusForbidden, resp.StatusCode)
	}
}

// TestInvalidCredentials checks that bad credentials return unauthorized.
func TestInvalidCredentials(t *testing.T) {
	ctx := setupTest(t)
	defer tearDown(t, ctx)

	resp := attemptLogin(t, ctx, nil, "admin", "bogus", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status %d but got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}

// TestSuccessfulLogin ensures valid credentials login successfully.
func TestSuccessfulLogin(t *testing.T) {
	ctx := setupTest(t)
	defer tearDown(t, ctx)

	resp := attemptLogin(t, ctx, nil, "admin", "gophish", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d but got %d", http.StatusOK, resp.StatusCode)
	}
}

// TestSuccessfulRedirect validates login redirect with a "next" parameter.
func TestSuccessfulRedirect(t *testing.T) {
	ctx := setupTest(t)
	defer tearDown(t, ctx)

	next := "/campaigns"
	client := &http.Client{
		// Prevent auto-following redirect, so we can inspect Location header.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp := attemptLogin(t, ctx, client, "admin", "gophish", fmt.Sprintf("?next=%s", next))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected status %d but got %d", http.StatusFound, resp.StatusCode)
	}

	location, err := resp.Location()
	if err != nil {
		t.Fatalf("error reading Location header: %v", err)
	}

	if location.Path != next {
		t.Fatalf("expected redirect to %s but got %s", next, location.Path)
	}
}

// TestAccountLocked verifies login fails for a locked account.
func TestAccountLocked(t *testing.T) {
	ctx := setupTest(t)
	defer tearDown(t, ctx)

	resp := attemptLogin(t, ctx, nil, "houdini", "gophish", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status %d but got %d", http.StatusUnauthorized, resp.StatusCode)
	}
}
