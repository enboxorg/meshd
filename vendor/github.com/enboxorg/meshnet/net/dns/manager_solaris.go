// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"github.com/enboxorg/meshnet/control/controlknobs"
	"github.com/enboxorg/meshnet/health"
	"github.com/enboxorg/meshnet/types/logger"
	"github.com/enboxorg/meshnet/util/eventbus"
	"github.com/enboxorg/meshnet/util/syspolicy/policyclient"
)

func NewOSConfigurator(logf logger.Logf, health *health.Tracker, bus *eventbus.Bus, _ policyclient.Client, _ *controlknobs.Knobs, iface string) (OSConfigurator, error) {
	return newDirectManager(logf, health, bus), nil
}
