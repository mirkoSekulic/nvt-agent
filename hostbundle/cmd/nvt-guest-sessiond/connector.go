//go:build !hostbundlesessiontest

package main

import "github.com/mirkoSekulic/nvt-agent/hostbundle/nativesession"

func configureConnector(*nativesession.TLSConnector) error { return nil }
