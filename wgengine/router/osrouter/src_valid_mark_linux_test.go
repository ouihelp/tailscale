// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android

package osrouter

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"tailscale.com/envknob"
)

func TestStrictRPFilterInterfaces(t *testing.T) {
	for all := 0; all <= 2; all++ {
		for iface := 0; iface <= 2; iface++ {
			t.Run(fmt.Sprintf("%d/%d", all, iface), func(t *testing.T) {
				conf := fstest.MapFS{
					"all/rp_filter":     {Data: []byte(fmt.Sprint(all))},
					"eth0/rp_filter":    {Data: []byte(fmt.Sprintf(" %d\n", iface))},
					"default/rp_filter": {Data: []byte("1")},
				}
				got, err := strictRPFilterInterfaces(conf)
				if err != nil {
					t.Fatal(err)
				}
				want := max(all, iface) == 1
				if (len(got) == 1) != want || (len(got) > 0 && got[0] != "eth0") {
					t.Fatalf("got %v, strict=%v", got, want)
				}
			})
		}
	}
	for _, conf := range []fstest.MapFS{
		{},
		{"all/rp_filter": {Data: []byte("bad")}},
		{"all/rp_filter": {Data: []byte("3")}},
		{"all/rp_filter": {Data: []byte("0")}, "eth0/other": {}},
		{"all/rp_filter": {Data: []byte("0")}, "eth0/rp_filter": {Data: []byte("-1")}},
	} {
		if _, err := strictRPFilterInterfaces(conf); err == nil {
			t.Errorf("expected reading error for %v", conf)
		}
	}
	// One unreadable interface must not hide a known strict interface.
	got, err := strictRPFilterInterfaces(fstest.MapFS{
		"all/rp_filter": {Data: []byte("0")}, "a/other": {}, "b/rp_filter": {Data: []byte("1")},
	})
	if err == nil || len(got) != 1 || got[0] != "b" {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestConfigureSrcValidMark(t *testing.T) {
	for _, knob := range []string{"", "false", "true"} {
		t.Run("knob="+knob, func(t *testing.T) {
			envknob.Setenv("TS_DISABLE_SRC_VALID_MARK", knob)
			t.Cleanup(func() { envknob.Setenv("TS_DISABLE_SRC_VALID_MARK", "") })
			for _, mode := range []string{"0", "1", "2", "bad"} {
				var once sync.Once
				writes := 0
				var logs []string
				conf := fstest.MapFS{"all/rp_filter": {Data: []byte("0")}, "eth0/rp_filter": {Data: []byte(mode)}}
				for range 3 {
					configureSrcValidMark(disableSrcValidMark(), &once, conf, func(k, v string) error {
						writes++
						if k != "net.ipv4.conf.all.src_valid_mark" || v != "1" {
							t.Fatalf("unexpected write %s=%s", k, v)
						}
						return errors.New("read-only test sysctl")
					}, func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
				}
				if knob != "true" {
					if writes != 3 || len(logs) != 3 || !strings.Contains(logs[0], "failed to enable") {
						t.Fatalf("writes=%d logs=%v", writes, logs)
					}
				} else {
					wantLogs := 1
					if mode == "1" || mode == "bad" {
						wantLogs = 2
					}
					if writes != 0 || len(logs) != wantLogs {
						t.Fatalf("mode=%s writes=%d logs=%v", mode, writes, logs)
					}
					if mode == "1" && !strings.Contains(logs[1], "effective strict rp_filter=1 on eth0") {
						t.Fatal(logs)
					}
					if mode == "bad" && !strings.Contains(logs[1], "could not fully inspect") {
						t.Fatal(logs)
					}
				}
			}
		})
	}
}
