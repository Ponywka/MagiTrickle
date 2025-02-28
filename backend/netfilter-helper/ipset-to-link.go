package netfilterHelper

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/coreos/go-iptables/iptables"
	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

type IPSetToLink struct {
	enabled atomic.Bool
	locker  sync.Mutex

	chainName string
	ifaceName string
	ipset     *IPSet
	nh        *NetfilterHelper
	mark      uint32
	table     int
	ip4Rule   *netlink.Rule
	ip6Rule   *netlink.Rule
	ip4Route  *netlink.Route
	ip6Route  *netlink.Route
}

func (r *IPSetToLink) insertIPTablesRules(ipt *iptables.IPTables, table string) error {
	if ipt == nil {
		return nil
	}
	if table == "" || table == "mangle" {
		err := ipt.NewChain("mangle", r.chainName)
		if err != nil {
			// If not "AlreadyExists"
			if eerr, eok := err.(*iptables.Error); !(eok && eerr.ExitStatus() == 1) {
				return fmt.Errorf("failed to create chain: %w", err)
			}
		}

		for _, iptablesArgs := range [][]string{
			{"-j", "CONNMARK", "--restore-mark"},
			{"-j", "MARK", "--set-mark", strconv.Itoa(int(r.mark))},
			{"-j", "CONNMARK", "--save-mark"},
		} {
			err = ipt.AppendUnique("mangle", r.chainName, iptablesArgs...)
			if err != nil {
				return fmt.Errorf("failed to append rule: %w", err)
			}
		}

		if ipt.Proto() == iptables.ProtocolIPv4 {
			err = ipt.InsertUnique("mangle", "PREROUTING", 1, "-m", "set", "--match-set", r.ipset.ipsetName+"_4", "dst", "-j", r.chainName)
			if err != nil {
				return fmt.Errorf("failed to append rule to PREROUTING: %w", err)
			}
		} else if ipt.Proto() == iptables.ProtocolIPv6 {
			err = ipt.InsertUnique("mangle", "PREROUTING", 1, "-m", "set", "--match-set", r.ipset.ipsetName+"_6", "dst", "-j", r.chainName)
			if err != nil {
				return fmt.Errorf("failed to append rule to PREROUTING: %w", err)
			}
		}
	}

	if table == "" || table == "nat" {
		err := ipt.NewChain("nat", r.chainName)
		if err != nil {
			// If not "AlreadyExists"
			if eerr, eok := err.(*iptables.Error); !(eok && eerr.ExitStatus() == 1) {
				return fmt.Errorf("failed to create chain: %w", err)
			}
		}

		err = ipt.AppendUnique("nat", r.chainName, "-j", "MASQUERADE")
		if err != nil {
			return fmt.Errorf("failed to create rule: %w", err)
		}

		if ipt.Proto() == iptables.ProtocolIPv4 {
			err = ipt.AppendUnique("nat", "POSTROUTING", "-m", "set", "--match-set", r.ipset.ipsetName+"_4", "dst", "-j", r.chainName)
			if err != nil {
				return fmt.Errorf("failed to append rule to POSTROUTING: %w", err)
			}
		} else if ipt.Proto() == iptables.ProtocolIPv6 {
			err = ipt.AppendUnique("nat", "POSTROUTING", "-m", "set", "--match-set", r.ipset.ipsetName+"_6", "dst", "-j", r.chainName)
			if err != nil {
				return fmt.Errorf("failed to append rule to POSTROUTING: %w", err)
			}
		}
	}

	return nil
}

func (r *IPSetToLink) deleteIPTablesRules(ipt *iptables.IPTables) error {
	if ipt == nil {
		return nil
	}
	var errs []error

	err := ipt.ClearChain("mangle", r.chainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to clear chain: %w", err))
	}

	if ipt.Proto() == iptables.ProtocolIPv4 {
		err = ipt.DeleteIfExists("mangle", "PREROUTING", "-m", "set", "--match-set", r.ipset.ipsetName+"_4", "dst", "-j", r.chainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to unlinking chain: %w", err))
		}
	} else if ipt.Proto() == iptables.ProtocolIPv6 {
		err = ipt.DeleteIfExists("mangle", "PREROUTING", "-m", "set", "--match-set", r.ipset.ipsetName+"_6", "dst", "-j", r.chainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to unlinking chain: %w", err))
		}
	}

	err = ipt.DeleteChain("mangle", r.chainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to delete chain: %w", err))
	}

	err = ipt.ClearChain("nat", r.chainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to clear chain: %w", err))
	}

	if ipt.Proto() == iptables.ProtocolIPv4 {
		err = ipt.DeleteIfExists("nat", "POSTROUTING", "-m", "set", "--match-set", r.ipset.ipsetName+"_4", "dst", "-j", r.chainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to unlinking chain: %w", err))
		}
	} else {
		err = ipt.DeleteIfExists("nat", "POSTROUTING", "-m", "set", "--match-set", r.ipset.ipsetName+"_6", "dst", "-j", r.chainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to unlinking chain: %w", err))
		}
	}

	err = ipt.ClearAndDeleteChain("nat", r.chainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to delete chain: %w", err))
	}

	return errors.Join(errs...)
}

func (r *IPSetToLink) insertIPRule() error {
	if r.nh.IPTables4 != nil {
		rule := netlink.NewRule()
		rule.Mark = r.mark
		rule.Table = r.table
		rule.Family = nl.FAMILY_V4
		_ = netlink.RuleDel(rule)
		err := netlink.RuleAdd(rule)
		if err != nil {
			return fmt.Errorf("error while mapping marked packages to table: %w", err)
		}
		r.ip4Rule = rule
	}

	if r.nh.IPTables6 != nil {
		rule := netlink.NewRule()
		rule.Mark = r.mark
		rule.Table = r.table
		rule.Family = nl.FAMILY_V6
		_ = netlink.RuleDel(rule)
		err := netlink.RuleAdd(rule)
		if err != nil {
			return fmt.Errorf("error while mapping marked packages to table: %w", err)
		}
		r.ip6Rule = rule
	}

	return nil
}

func (r *IPSetToLink) deleteIPRule() error {
	var errs []error

	if r.nh.IPTables4 != nil && r.ip4Rule != nil {
		err := netlink.RuleDel(r.ip4Rule)
		if err != nil {
			errs = append(errs, fmt.Errorf("error while deleting rule: %w", err))
		}
		r.ip4Rule = nil
	}

	if r.nh.IPTables6 != nil && r.ip6Rule != nil {
		err := netlink.RuleDel(r.ip6Rule)
		if err != nil {
			errs = append(errs, fmt.Errorf("error while deleting rule: %w", err))
		}
		r.ip6Rule = nil
	}

	return errors.Join(errs...)
}

func (r *IPSetToLink) insertIPRoute() error {
	iface, err := netlink.LinkByName(r.ifaceName)
	if err != nil {
		if errors.As(err, &netlink.LinkNotFoundError{}) {
			log.Warn().Str("iface", r.ifaceName).Msg("interface not found, it can be catched later")
			return nil
		}
		return fmt.Errorf("error while getting interface: %w", err)
	}
	if iface.Attrs().Flags&net.FlagUp == 0 {
		log.Warn().Str("iface", r.ifaceName).Msg("interface is down")
		return nil
	}

	if r.nh.IPTables4 != nil {
		route := &netlink.Route{
			Family:    nl.FAMILY_V4,
			LinkIndex: iface.Attrs().Index,
			Table:     r.table,
			Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		}
		err = netlink.RouteAdd(route)
		if err != nil {
			// TODO: Нормально отлавливать ошибку
			if err.Error() == "file exists" {
				r.ip4Route = route
				return nil
			}
			return fmt.Errorf("error while adding route: %w", err)
		}
		r.ip4Route = route
	}

	if r.nh.IPTables6 != nil {
		route := &netlink.Route{
			Family:    nl.FAMILY_V6,
			LinkIndex: iface.Attrs().Index,
			Table:     r.table,
			Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		}
		err = netlink.RouteAdd(route)
		if err != nil {
			// TODO: Нормально отлавливать ошибку
			if err.Error() == "file exists" {
				r.ip6Route = route
				return nil
			}
			return fmt.Errorf("error while adding route: %w", err)
		}
		r.ip6Route = route
	}

	return nil
}

func (r *IPSetToLink) deleteIPRoute() error {
	var errs []error

	if r.nh.IPTables4 != nil && r.ip4Route != nil {
		err := netlink.RouteDel(r.ip4Route)
		if err != nil {
			errs = append(errs, fmt.Errorf("error while deleting route: %w", err))
		}
		r.ip4Route = nil
	}

	if r.nh.IPTables6 != nil && r.ip6Route != nil {
		err := netlink.RouteDel(r.ip6Route)
		if err != nil {
			errs = append(errs, fmt.Errorf("error while deleting route: %w", err))
		}
		r.ip6Route = nil
	}

	return nil
}

func (r *IPSetToLink) getUnusedMarkAndTable() (mark uint32, table int, err error) {
	// Find unused mark and table
	markMap := make(map[uint32]struct{})
	tableMap := map[int]struct{}{0: {}, 253: {}, 254: {}, 255: {}}

	rules, err := netlink.RuleList(nl.FAMILY_ALL)
	if err != nil {
		return 0, 0, fmt.Errorf("error while getting rules: %w", err)
	}
	for _, rule := range rules {
		markMap[rule.Mark] = struct{}{}
		tableMap[rule.Table] = struct{}{}
	}

	routes, err := netlink.RouteListFiltered(nl.FAMILY_ALL, &netlink.Route{}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return 0, 0, fmt.Errorf("error while getting routes: %w", err)
	}
	for _, route := range routes {
		tableMap[route.Table] = struct{}{}
	}

	for table = 0; table < 0x7ffffffe; table++ {
		if _, exists := tableMap[table]; !exists {
			break
		}
	}

	for mark = 0; mark < 0xfffffffe; mark++ {
		if _, exists := markMap[mark]; !exists {
			break
		}
	}

	return mark, table, nil
}

func (r *IPSetToLink) enable() error {
	if !r.enabled.CompareAndSwap(false, true) {
		return nil
	}

	var err error
	r.mark, r.table, err = r.getUnusedMarkAndTable()
	if err != nil {
		return err
	}

	err = r.deleteIPTablesRules(r.nh.IPTables4)
	if err != nil {
		return err
	}

	err = r.insertIPTablesRules(r.nh.IPTables4, "")
	if err != nil {
		return err
	}

	err = r.deleteIPTablesRules(r.nh.IPTables6)
	if err != nil {
		return err
	}

	err = r.insertIPTablesRules(r.nh.IPTables6, "")
	if err != nil {
		return err
	}

	err = r.insertIPRule()
	if err != nil {
		return err
	}

	err = r.insertIPRoute()
	if err != nil {
		return err
	}

	return nil
}

func (r *IPSetToLink) Enable() error {
	r.locker.Lock()
	defer r.locker.Unlock()

	err := r.enable()
	if err != nil {
		r.disable()
	} else {
		log.Trace().Int("table", r.table).Int("mark", int(r.mark)).Msg("using ip table and mark")
	}

	return err
}

func (r *IPSetToLink) disable() error {
	if !r.enabled.Load() {
		return nil
	}
	defer r.enabled.Store(false)

	var errs []error
	errs = append(errs, r.deleteIPRoute())
	errs = append(errs, r.deleteIPRule())
	errs = append(errs, r.deleteIPTablesRules(r.nh.IPTables4))
	errs = append(errs, r.deleteIPTablesRules(r.nh.IPTables6))
	return errors.Join(errs...)
}

func (r *IPSetToLink) Disable() error {
	r.locker.Lock()
	defer r.locker.Unlock()

	return r.disable()
}

func (r *IPSetToLink) NetfilterDHook(iptType, table string) error {
	r.locker.Lock()
	defer r.locker.Unlock()

	if !r.enabled.Load() {
		return nil
	}

	if iptType == "" || iptType == "iptables" {
		err := r.insertIPTablesRules(r.nh.IPTables4, table)
		if err != nil {
			return err
		}
	}
	if iptType == "" || iptType == "ip6tables" {
		err := r.insertIPTablesRules(r.nh.IPTables6, table)
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *IPSetToLink) LinkUpdateHook(event netlink.LinkUpdate) error {
	r.locker.Lock()
	defer r.locker.Unlock()

	if !r.enabled.Load() || event.Change != 1 || event.Link.Attrs().Name != r.ifaceName {
		return nil
	}

	return r.insertIPRoute()
}

func (nh *NetfilterHelper) IPSetToLink(name string, ifaceName string, ipset *IPSet) *IPSetToLink {
	return &IPSetToLink{
		nh:        nh,
		chainName: nh.ChainPrefix + name,
		ifaceName: ifaceName,
		ipset:     ipset,
	}
}
