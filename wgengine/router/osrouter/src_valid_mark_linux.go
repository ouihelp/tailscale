// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android

package osrouter

import (
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"sync"

	"tailscale.com/envknob"
	"tailscale.com/types/logger"
)

var disableSrcValidMark = envknob.RegisterBool("TS_DISABLE_SRC_VALID_MARK")

// configureSrcValidMark preserves the upstream write unless explicitly opted out.
// Diagnostics are a snapshot, once per router lifetime, not a sysctl monitor.
func configureSrcValidMark(disabled bool, once *sync.Once, conf fs.FS, write func(string, string) error, logf logger.Logf) {
	if !disabled {
		if err := write("net.ipv4.conf.all.src_valid_mark", "1"); err != nil {
			logf("warning: failed to enable src_valid_mark: %v", err)
		}
		return
	}
	once.Do(func() {
		logf("TS_DISABLE_SRC_VALID_MARK=true: leaving src_valid_mark unchanged; administrator is responsible for reverse-path filtering compatibility")
		strict, err := strictRPFilterInterfaces(conf)
		if len(strict) != 0 {
			logf("warning: TS_DISABLE_SRC_VALID_MARK=true with effective strict rp_filter=1 on %s: traffic may be dropped; review RPF routing or explicitly configure loose mode where appropriate (no sysctls changed)", strings.Join(strict, ", "))
		}
		if err != nil {
			logf("warning: TS_DISABLE_SRC_VALID_MARK=true: could not fully inspect effective rp_filter: %v; verify all and per-interface settings manually", err)
		}
	})
}

// Linux uses max(conf/all/rp_filter, conf/<iface>/rp_filter). The default
// directory is only a template for newly created interfaces, not an override.
func strictRPFilterInterfaces(conf fs.FS) ([]string, error) {
	read := func(name string) (int, error) {
		b, err := fs.ReadFile(conf, name+"/rp_filter")
		if err != nil {
			return 0, err
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || n < 0 || n > 2 {
			return 0, fmt.Errorf("invalid %s/rp_filter: %q", name, b)
		}
		return n, nil
	}
	all, err := read("all")
	if err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(conf, ".")
	if err != nil {
		return nil, err
	}
	var strict []string
	var firstErr error
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "all" || e.Name() == "default" {
			continue
		}
		mode, err := read(e.Name())
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if max(all, mode) == 1 {
			strict = append(strict, e.Name())
		}
	}
	return strict, firstErr
}
