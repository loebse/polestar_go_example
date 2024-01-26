package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

const (
	baseURL      = "https://polestarid.eu.polestar.com" // Update this line
	authEndpoint = "/as/authorization.oauth2"
	callbackURL  = "https://www.polestar.com/sign-in-callback"
)

type PolestarAuth struct {
	Username       string
	Password       string
	AccessToken    string
	RefreshToken   string
	TokenExpiry    time.Time
	LatestCallCode int
	Client         *http.Client
}

func NewPolestarAuth(username, password string, client *http.Client) *PolestarAuth {
	return &PolestarAuth{
		Username: username,
		Password: password,
		Client:   client, // Use the provided client
	}
}

func (p *PolestarAuth) GetToken(refresh bool) error {
	var (
		err        error
		code       string
		resumePath string
		endpoint   string
		operation  string
	)

	if !refresh || p.TokenExpiry.IsZero() || time.Now().After(p.TokenExpiry) {
		resumePath, err = p.getResumePath()
		if err != nil {
			return err
		}

		code, err = p.getCode(resumePath)
		if err != nil {
			return err
		}

		endpoint = authEndpoint
		operation = "getAuthToken"
	} else {
		if p.RefreshToken == "" {
			return fmt.Errorf("refresh token is empty")
		}
		code = p.RefreshToken
		endpoint = authEndpoint
		operation = "refreshAuthToken"
	}

	params := map[string]interface{}{
		"query":         fmt.Sprintf("query %s($code: String!) { %s(code: $code) { id_token access_token refresh_token expires_in }}", operation, operation),
		"operationName": operation,
		"variables":     json.RawMessage(fmt.Sprintf(`{"code": "%s"}`, code)),
	}

	body, err := json.Marshal(params)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("GET", baseURL+endpoint, strings.NewReader(string(body)))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	p.LatestCallCode = resp.StatusCode

	var resultData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&resultData); err != nil {
		return err
	}

	if resultData["data"] != nil {
		p.AccessToken = resultData["data"].(map[string]interface{})[operation].(map[string]interface{})["access_token"].(string)
		p.RefreshToken = resultData["data"].(map[string]interface{})[operation].(map[string]interface{})["refresh_token"].(string)
		expiresIn := resultData["data"].(map[string]interface{})[operation].(map[string]interface{})["expires_in"].(float64)
		p.TokenExpiry = time.Now().Add(time.Second * time.Duration(expiresIn))
	}

	fmt.Printf("Access Token: %s\n", p.AccessToken)
	fmt.Printf("Refresh Token: %s\n", p.RefreshToken)
	fmt.Printf("Token Expiry: %s\n", p.TokenExpiry)

	return nil
}

func (p *PolestarAuth) getCode(resumePath string) (string, error) {
	// Step 1: Perform a POST request to obtain the initial redirect URL
	postURL := baseURL + fmt.Sprintf("/as/%s/resume/as/authorization.ping", resumePath)
	params := url.Values{"client_id": {"polmystar"}}

	// Additional parameters in the URL
	if len(params) > 0 {
		postURL += "?" + params.Encode()
	}

	// Additional parameters in the URL
	formData := url.Values{
		"pf.username": {p.Username},
		"pf.pass":     {p.Password},
	}

	fmt.Printf("POST URL: %s\n", postURL)
	fmt.Printf("POST Form Data: %+v\n", formData)

	// Use a custom client to handle redirection manually
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Perform the POST request
	resp, err := client.PostForm(postURL, formData)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	p.LatestCallCode = resp.StatusCode

	// Check for a 302 status code indicating a successful POST request
	if resp.StatusCode != http.StatusFound {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Extract the code from the Location header of the first redirect
	code, err := extractCodeFromURL(resp.Header.Get("Location"))
	if err != nil {
		return "", err
	}

	fmt.Printf("Extracted code: %s\n", code)

	return code, nil
}

// func (p *PolestarAuth) getCode(resumePath string) (string, error) {
// 	// Step 1: Perform a POST request to obtain the initial redirect URL
// 	postURL := baseURL + fmt.Sprintf("/as/%s/resume/as/authorization.ping", resumePath)
// 	params := url.Values{"client_id": {"polmystar"}}

// 	// Additional parameters in the URL
// 	if len(params) > 0 {
// 		postURL += "?" + params.Encode()
// 	}

// 	// Additional parameters in the URL
// 	formData := url.Values{
// 		"pf.username": {p.Username},
// 		"pf.pass":     {p.Password},
// 	}

// 	fmt.Printf("POST URL: %s\n", postURL)
// 	fmt.Printf("POST Form Data: %+v\n", formData)

// 	// Use http.DefaultClient for the POST request (uses automatic redirect following)
// 	resp, err := http.DefaultClient.PostForm(postURL, formData)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer resp.Body.Close()

// 	p.LatestCallCode = resp.StatusCode

// 	// Check for a 302 status code indicating a successful POST request
// 	if resp.StatusCode != http.StatusFound {
// 		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
// 	}

// 	// Extract the code from the Location header of the first redirect
// 	code, err := extractCodeFromURL(resp.Header.Get("Location"))
// 	if err != nil {
// 		return "", err
// 	}

// 	fmt.Printf("Extracted code: %s\n", code)

// 	return code, nil
// }

func (p *PolestarAuth) getResumePath() (string, error) {
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {"polmystar"},
		"redirect_uri":  {callbackURL},
	}

	// Configure the client to not follow redirects automatically
	redirectClient := p.Client
	redirectClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	fullURL := baseURL + authEndpoint + "?" + params.Encode()

	fmt.Printf("Request URL: %s\n", fullURL)

	resp, err := redirectClient.Get(fullURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	p.LatestCallCode = resp.StatusCode

	fmt.Printf("Response Status Code: %d\n", resp.StatusCode)

	// Check for a 303 status code indicating a redirect
	if resp.StatusCode == http.StatusSeeOther {
		location := resp.Header.Get("Location")
		fmt.Printf("Redirect Location: %s\n", location)

		// Extract resumePath from the Location header
		resumePath := extractResumePath(location)
		if resumePath == "" {
			return "", fmt.Errorf("unable to extract resumePath from URL")
		}
		return resumePath, nil
	}

	return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}

func extractCodeFromURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	queryParams, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", err
	}

	return queryParams.Get("code"), nil
}

func extractResumePath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	queryParams, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return ""
	}

	return queryParams.Get("resumePath")
}

func main() {
	godotenv.Load(".env")

	username := os.Getenv("username")
	password := os.Getenv("password")

	// Create a shared HTTP client
	client := &http.Client{}

	polestarAuth := NewPolestarAuth(username, password, client)

	err := polestarAuth.GetToken(false)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}
}
