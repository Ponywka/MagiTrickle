//go:build kn

package magitrickle

import "fmt"

func (g *Group) routerSpecificPatches(iptType, table string) error {
	if table == "" || table == "filter" {
		if (iptType == "" || iptType == "ip4tables") && g.app.nfHelper.IPTables4 != nil {
			err := g.app.nfHelper.IPTables4.AppendUnique("filter", "_NDM_SL_FORWARD", "-o", g.Interface, "-m", "state", "--state", "NEW", "-j", "_NDM_SL_PROTECT")
			if err != nil {
				return fmt.Errorf("failed to fix protect for IPv4: %w", err)
			}
		}
		if (iptType == "" || iptType == "ip6tables") && g.app.nfHelper.IPTables6 != nil {
			err := g.app.nfHelper.IPTables6.AppendUnique("filter", "_NDM_SL_FORWARD", "-o", g.Interface, "-j", "_NDM_SL_PROTECT")
			if err != nil {
				return fmt.Errorf("failed to fix protect for IPv6: %w", err)
			}
		}
	}
	return nil
}
