//go:build !hostbundleegresstest

package main

import "github.com/mirkoSekulic/nvt-agent/hostbundle/nativeegress"

func configureConnector(*nativeegress.TLSConnector) error { return nil }
