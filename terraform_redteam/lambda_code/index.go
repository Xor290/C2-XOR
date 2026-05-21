package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

var (
	ec2URL     = os.Getenv("EC2_URL")
	httpClient = &http.Client{Timeout: 10 * time.Second}
)

func lambdaHandler(ctx context.Context, event events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	method := event.HTTPMethod
	if method == "" {
		method = "GET"
	}
	path := event.Path
	if path == "" {
		path = "/"
	}

	targetURL := ec2URL + path
	if len(event.QueryStringParameters) > 0 {
		parts := make([]string, 0, len(event.QueryStringParameters))
		for k, v := range event.QueryStringParameters {
			parts = append(parts, k+"="+v)
		}
		targetURL += "?" + strings.Join(parts, "&")
	}

	var bodyBytes []byte
	if event.Body != "" {
		if event.IsBase64Encoded {
			var err error
			bodyBytes, err = base64.StdEncoding.DecodeString(event.Body)
			if err != nil {
				return errResponse(502, "base64 decode: "+err.Error()), nil
			}
		} else {
			bodyBytes = []byte(event.Body)
		}
	}

	var bodyReader io.Reader
	if len(bodyBytes) > 0 {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return errResponse(502, "build request: "+err.Error()), nil
	}

	for k, v := range event.Headers {
		lower := strings.ToLower(k)
		if lower == "host" || lower == "x-forwarded-for" {
			continue
		}
		req.Header.Set(k, v)
	}
	if len(bodyBytes) > 0 {
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(bodyBytes)))
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return errResponse(502, err.Error()), nil
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return errResponse(502, "read response: "+err.Error()), nil
	}

	var respBody string
	var isB64 bool
	if utf8.Valid(respBytes) {
		respBody = string(respBytes)
	} else {
		respBody = base64.StdEncoding.EncodeToString(respBytes)
		isB64 = true
	}

	return events.APIGatewayProxyResponse{
		StatusCode:      resp.StatusCode,
		Headers:         map[string]string{"Content-Type": "application/octet-stream"},
		IsBase64Encoded: isB64,
		Body:            respBody,
	}, nil
}

func errResponse(code int, msg string) events.APIGatewayProxyResponse {
	body, _ := json.Marshal(map[string]string{"error": msg})
	return events.APIGatewayProxyResponse{
		StatusCode: code,
		Body:       string(body),
	}
}

func main() {
	lambda.Start(lambdaHandler)
}
