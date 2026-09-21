// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package linuxfw

import (
	"encoding/binary"
	"strconv"
	"testing"
)

func TestOuihelpMarkAllocation(t *testing.T) {
	for _, tt := range []struct {
		name, text string
		num, want  uint32
		bytes      []byte
	}{
		{"mask", fwmarkMask, fwmarkMaskNum, 0xf000, getTailscaleFwmarkMask()},
		{"subnet", subnetRouteMark, subnetRouteMarkNum, 0x1000, getTailscaleSubnetRouteMark()},
		{"bypass", bypassMark, bypassMarkNum, 0x2000, nativeEndianUint32(bypassMarkNum)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := strconv.ParseUint(tt.text, 0, 32)
			if err != nil || uint32(parsed) != tt.want || tt.num != tt.want || binary.NativeEndian.Uint32(tt.bytes) != tt.want {
				t.Fatalf("inconsistent mark allocation: %+v", tt)
			}
		})
	}
	neg := binary.NativeEndian.Uint32(getTailscaleFwmarkMaskNeg())
	if neg != 0xffff0fff {
		t.Fatalf("negative mask=%#x", neg)
	}
	// Setting subnet marks must retain all bits outside our allocation.
	for _, mark := range []uint32{0, 0x80000, 0xff0000, 0xffffffff, 0x12345678} {
		got := (mark & neg) ^ subnetRouteMarkNum
		if got & ^uint32(fwmarkMaskNum) != mark & ^uint32(fwmarkMaskNum) || got&fwmarkMaskNum != subnetRouteMarkNum {
			t.Fatalf("mark=%#x got=%#x", mark, got)
		}
	}
}
