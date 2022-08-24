// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/flag"
)

//go:embed bpf/redirect_ebpf.o
var redirectProgram []byte

// RedirectCommand is a subcommands for redirect packets between devices.
type RedirectCommand struct {
	from      string
	fromIndex int
	to        string
	toIndex   int
	ipStr     string
}

// Name implements subcommands.Command.Name.
func (*RedirectCommand) Name() string {
	return "redirect"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*RedirectCommand) Synopsis() string {
	return "Redirect packets from one interface to another."
}

// Usage implements subcommands.Command.Usage.
func (*RedirectCommand) Usage() string {
	return "redirect -from[Idx] <device or index> -to[Idx] <device or index> -ip <IP address>"
}

// SetFlags implements subcommands.Command.SetFlags.
func (rc *RedirectCommand) SetFlags(fs *flag.FlagSet) {
	fs.StringVar(&rc.from, "from", "", "which device to redirect from")
	fs.IntVar(&rc.fromIndex, "fromIdx", 0, "which device to redirect from")
	fs.StringVar(&rc.to, "to", "", "which device to redirect to")
	fs.IntVar(&rc.toIndex, "toIdx", 0, "which device to redirect to")
	fs.StringVar(&rc.ipStr, "ip", "", "the destination address for which all packets should be redirected")
}

// Execute implements subcommands.Command.Execute.
func (rc *RedirectCommand) Execute(context.Context, *flag.FlagSet, ...interface{}) subcommands.ExitStatus {
	if err := rc.execute(); err != nil {
		log.Printf("%v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (rc *RedirectCommand) execute() error {
	from, err := getIface(rc.from, rc.fromIndex)
	if err != nil {
		return fmt.Errorf("failed to get from iface: %v", err)
	}
	to, err := getIface(rc.to, rc.toIndex)
	if err != nil {
		return fmt.Errorf("failed to get from iface: %v", err)
	}

	ip := net.ParseIP(rc.ipStr)
	if ip.To4() == nil {
		return fmt.Errorf("invalid IPv4 address: %s", rc.ipStr)
	}

	// Load the BPF program into the kernel.
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(redirectProgram))
	if err != nil {
		return fmt.Errorf("failed to load spec: %v", err)
	}

	var objects struct {
		Program *ebpf.Program `ebpf:"xdp_prog"`
		IPMap   *ebpf.Map     `ebpf:"ip_map"`
		DevMap  *ebpf.Map     `ebpf:"dev_map"`
	}
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		return fmt.Errorf("failed to load program: %v", err)
	}
	defer func() {
		if err := objects.Program.Close(); err != nil {
			log.Printf("failed to close program: %v", err)
		}
		if err := objects.IPMap.Close(); err != nil {
			log.Printf("failed to close sock map: %v", err)
		}
		if err := objects.DevMap.Close(); err != nil {
			log.Printf("failed to close sock map: %v", err)
		}
	}()

	// Attach the program to the "from" interface.
	cleanup, err := attach(objects.Program, from)
	if err != nil {
		return fmt.Errorf("failed to attach: %v", err)
	}
	defer cleanup()

	// Insert our "to" interface into the BPF map.
	key := uint32(0)
	val := uint32(to.Index)
	if err := objects.DevMap.Update(&key, &val, 0 /* flags */); err != nil {
		return fmt.Errorf("failed to insert device into BPF map: %v", err)
	}
	log.Printf("updated key %d to value %d", key, val)

	// Insert the IP address into the BPF map.
	val = binary.LittleEndian.Uint32(ip.To4())
	if err := objects.IPMap.Update(&key, &val, 0 /* flags */); err != nil {
		return fmt.Errorf("failed to insert IP into BPF map: %v", err)
	}
	log.Printf("updated key %d to value %d", key, val)

	waitForever()
	return nil
}
