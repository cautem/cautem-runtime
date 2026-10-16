// Package inference is the product catalog / helpers for LLM egress (P5).
//
// cautem does not ship a managed inference.local rewrite proxy. Agents call
// provider native hosts; policy.inference.providers expands into CONNECT
// allow rules, and matching API keys are injected from the host env.
package inference

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/cautem/quarshell-core/policy"
)

// ListBuiltins writes the builtin provider catalog.
func ListBuiltins(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tHOSTS\tENV")
	for _, id := range policy.KnownProviderIDs() {
		p := policy.BuiltinProviders[id]
		var hosts []string
		for _, r := range p.Rules {
			ports := r.EffectivePorts()
			ps := make([]string, 0, len(ports))
			for _, port := range ports {
				ps = append(ps, fmt.Sprintf("%d", port))
			}
			hosts = append(hosts, fmt.Sprintf("%s:%s", r.Host, strings.Join(ps, ",")))
		}
		env := "-"
		if len(p.EnvKeys) > 0 {
			env = strings.Join(p.EnvKeys, ",")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", id, strings.Join(hosts, "; "), env)
	}
	return tw.Flush()
}

// ShowEffective prints providers + merged allow rules + credential env keys for a doc.
func ShowEffective(w io.Writer, doc policy.Document) error {
	if doc.Inference != nil && len(doc.Inference.Providers) > 0 {
		fmt.Fprintf(w, "providers: %s\n", strings.Join(doc.Inference.Providers, ", "))
	} else {
		fmt.Fprintln(w, "providers: (none)")
	}
	fmt.Fprintf(w, "credential_env: %s\n", strings.Join(doc.CredentialEnvKeys(), ", "))
	rules := doc.AllowRules()
	fmt.Fprintf(w, "allow_rules: %d\n", len(rules))
	for _, r := range rules {
		ports := r.EffectivePorts()
		ps := make([]string, 0, len(ports))
		for _, p := range ports {
			ps = append(ps, fmt.Sprintf("%d", p))
		}
		id := r.ID
		if id == "" {
			id = "-"
		}
		fmt.Fprintf(w, "  - %s  %s:%s\n", id, r.Host, strings.Join(ps, ","))
	}
	return nil
}

// WriteLocalSnippet prints a ready-to-use host-local inference policy fragment.
func WriteLocalSnippet(w io.Writer) error {
	_, err := io.WriteString(w, `# Host-local models (no inference.local rewrite proxy).
# Agents call http://host.cautem.internal:<port>/v1/...
version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /etc]
  read_write: [/tmp]
landlock:
  compatibility: best_effort
network_policies: {}
inference:
  providers: [local]
  # Or pin one server via profiles:
  # profiles:
  #   - id: vllm
  #     host: host.cautem.internal
  #     port: 8000
  #     env_keys: [OPENAI_API_KEY]
  #     refresh: env
`)
	return err
}
