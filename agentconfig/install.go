// SPDX-FileCopyrightText: Copyright (c) 2026 cautem
// SPDX-License-Identifier: Apache-2.0

package agentconfig

import (
	"fmt"
)

// Guest is the minimal sandbox surface needed to install supervisor guidance.
type Guest interface {
	ExecRaw(argv []string) error
	CopyTo(hostSrc, guestDest string) error
}

// Install puts supervisor-owned policy guidance in the reserved control tree
// and writes the root pointer only when the image does not already provide one.
func Install(g Guest, st Staged) error {
	if g == nil {
		return fmt.Errorf("agentconfig: nil guest")
	}
	if err := g.CopyTo(st.EtcOSGHost, "/etc"); err != nil {
		return fmt.Errorf("agentconfig: /etc/cautem: %w", err)
	}
	installAgents := fmt.Sprintf(`if [ -w / ] && [ ! -e /%s ] && [ ! -L /%s ]; then cp /etc/cautem/%s /%s; fi`, agentsMDName, agentsMDName, agentsMDName, agentsMDName)
	if err := g.ExecRaw([]string{"/bin/sh", "-c", installAgents}); err != nil {
		return fmt.Errorf("agentconfig: /AGENTS.md: %w", err)
	}
	return nil
}
