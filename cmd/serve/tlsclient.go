package main

// tls-client adapter: the browser-fingerprint client in
// github.com/bogdanfinn/tls-client operates on fhttp Request/Response
// types (a fork of net/http), while internal/models talks to the scraper
// through models.Doer (net/http types). This adapter bridges the two by
// mapping the fields the scraper actually uses.

import (
	"net/http"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

// tlsClientAdapter adapts tls_client.HttpClient to models.Doer.
type tlsClientAdapter struct {
	c tlsclient.HttpClient
}

// Do performs req through the fingerprint-impersonating client and maps
// the fhttp response back to net/http types.
func (a tlsClientAdapter) Do(req *http.Request) (*http.Response, error) {
	fr := &fhttp.Request{
		Method:           req.Method,
		URL:              req.URL,
		Proto:            req.Proto,
		ProtoMajor:       req.ProtoMajor,
		ProtoMinor:       req.ProtoMinor,
		Header:           fhttp.Header(req.Header),
		Body:             req.Body,
		GetBody:          req.GetBody,
		ContentLength:    req.ContentLength,
		TransferEncoding: req.TransferEncoding,
		Close:            req.Close,
		Host:             req.Host,
	}
	resp, err := a.c.Do(fr)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		Status:           resp.Status,
		StatusCode:       resp.StatusCode,
		Proto:            resp.Proto,
		ProtoMajor:       resp.ProtoMajor,
		ProtoMinor:       resp.ProtoMinor,
		Header:           http.Header(resp.Header),
		Body:             resp.Body,
		ContentLength:    resp.ContentLength,
		TransferEncoding: resp.TransferEncoding,
		Close:            resp.Close,
		Uncompressed:     resp.Uncompressed,
		Trailer:          http.Header(resp.Trailer),
	}, nil
}
