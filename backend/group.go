package magitrickle

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"magitrickle/models"
	"magitrickle/netfilter-helper"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
)

type Group struct {
	*models.Group

	enabled atomic.Bool
	locker  sync.Mutex

	app         *App
	ipset       *netfilterHelper.IPSet
	ipsetToLink *netfilterHelper.IPSetToLink
}

func (g *Group) addIP(address net.IP, ttl uint32) error {
	return g.ipset.AddIP(address, &ttl)
}

func (g *Group) AddIP(address net.IP, ttl uint32) error {
	g.locker.Lock()
	defer g.locker.Unlock()

	if !g.enabled.Load() {
		return nil
	}

	if !g.Group.Enable {
		return nil
	}

	return g.addIP(address, ttl)
}

func (g *Group) delIP(address net.IP) error {
	return g.ipset.DelIP(address)
}

func (g *Group) DelIP(address net.IP) error {
	g.locker.Lock()
	defer g.locker.Unlock()

	if !g.enabled.Load() {
		return nil
	}

	if !g.Group.Enable {
		return nil
	}

	return g.delIP(address)
}

func (g *Group) listIPs() (map[string]*uint32, error) {
	return g.ipset.ListIPs()
}

func (g *Group) ListIPs() (map[string]*uint32, error) {
	g.locker.Lock()
	defer g.locker.Unlock()

	if !g.enabled.Load() {
		return nil, nil
	}

	if !g.Group.Enable {
		return nil, nil
	}

	return g.listIPs()
}

func (g *Group) createIPSet() error {
	ipset := g.app.nfHelper.IPSet(g.ID.String())
	err := ipset.Enable()
	if err != nil {
		return fmt.Errorf("failed to initialize ipset: %w", err)
	}
	g.ipset = ipset
	return nil
}

func (g *Group) deleteIPSet() error {
	if g.ipset == nil {
		return nil
	}

	err := g.ipset.Disable()
	if err != nil {
		return fmt.Errorf("failed to destroy ipset: %w", err)
	}
	g.ipset = nil
	return nil
}

func (g *Group) linkIfaceToIPSet() error {
	ipsetToLink := g.app.nfHelper.IPSetToLink(g.ID.String(), g.Interface, g.ipset)
	err := ipsetToLink.Enable()
	if err != nil {
		return fmt.Errorf("failed to link ipset to interface: %w", err)
	}
	g.ipsetToLink = ipsetToLink
	return nil
}

func (g *Group) unlinkIfaceFromIPSet() error {
	if g.ipsetToLink == nil {
		return nil
	}

	err := g.ipsetToLink.Disable()
	if err != nil {
		return fmt.Errorf("failed to unlink ipset to interface: %w", err)
	}
	g.ipsetToLink = nil
	return nil
}

func (g *Group) enable() error {
	if !g.enabled.CompareAndSwap(false, true) {
		return nil
	}

	if !g.Group.Enable {
		return nil
	}

	err := g.createIPSet()
	if err != nil {
		return err
	}

	err = g.linkIfaceToIPSet()
	if err != nil {
		return err
	}

	err = g.routerSpecificPatches("", "")
	if err != nil {
		return err
	}

	return nil
}

func (g *Group) Enable() error {
	g.locker.Lock()
	defer g.locker.Unlock()

	err := g.enable()
	if err != nil {
		g.disable()
	}

	return err
}

func (g *Group) disable() error {
	if !g.enabled.Load() {
		return nil
	}
	defer g.enabled.Store(false)

	if !g.Group.Enable {
		return nil
	}

	var errs []error
	errs = append(errs, g.unlinkIfaceFromIPSet())
	errs = append(errs, g.deleteIPSet())
	return errors.Join(errs...)
}

func (g *Group) Disable() error {
	g.locker.Lock()
	defer g.locker.Unlock()

	return g.disable()
}

func (g *Group) Sync() error {
	g.locker.Lock()
	defer g.locker.Unlock()

	if !g.enabled.Load() {
		return nil
	}

	if !g.Group.Enable {
		return nil
	}

	now := time.Now()

	addresses := make(map[string]uint32)
	knownDomains := g.app.records.ListKnownDomains()
	for _, domain := range g.Rules {
		if !domain.IsEnabled() {
			continue
		}

		for _, domainName := range knownDomains {
			if !domain.IsMatch(domainName) {
				continue
			}

			domainAddresses := g.app.records.GetIPRecords(domainName)
			for _, address := range domainAddresses {
				ttl := uint32(now.Sub(address.Deadline).Seconds())
				if oldTTL, ok := addresses[string(address.Address)]; !ok || ttl > oldTTL {
					addresses[string(address.Address)] = ttl
				}
			}
		}
	}

	currentAddresses, err := g.listIPs()
	if err != nil {
		return fmt.Errorf("failed to get old ipset list: %w", err)
	}

	for addr, ttl := range addresses {
		if _, exists := currentAddresses[addr]; exists {
			if currentAddresses[addr] == nil {
				continue
			} else {
				if ttl < *currentAddresses[addr] {
					continue
				}
			}
		}
		ip := net.IP(addr)
		err = g.addIP(ip, ttl)
		if err != nil {
			log.Error().
				Str("address", ip.String()).
				Err(err).
				Msg("failed to add address")
		} else {
			log.Trace().
				Str("address", ip.String()).
				Err(err).
				Msg("add address")
		}
	}

	for addr := range currentAddresses {
		if _, ok := addresses[addr]; ok {
			continue
		}
		ip := net.IP(addr)
		err = g.delIP(ip)
		if err != nil {
			log.Error().
				Str("address", ip.String()).
				Err(err).
				Msg("failed to delete address")
		} else {
			log.Trace().
				Str("address", ip.String()).
				Err(err).
				Msg("del address")
		}
	}

	return nil
}

func (g *Group) NetfilterDHook(iptType, table string) error {
	g.locker.Lock()
	defer g.locker.Unlock()

	if !g.enabled.Load() {
		return nil
	}

	if !g.Group.Enable {
		return nil
	}

	var errs []error
	if g.enabled.Load() {
		errs = append(errs, g.routerSpecificPatches(iptType, table))
		errs = append(errs, g.ipsetToLink.NetfilterDHook(iptType, table))
	}

	return errors.Join(errs...)
}

func (g *Group) LinkUpdateHook(event netlink.LinkUpdate) error {
	g.locker.Lock()
	defer g.locker.Unlock()

	if !g.enabled.Load() {
		return nil
	}

	if !g.Group.Enable {
		return nil
	}

	var errs []error
	if g.enabled.Load() {
		errs = append(errs, g.routerSpecificPatches("", ""))
		errs = append(errs, g.ipsetToLink.LinkUpdateHook(event))
	}

	return errors.Join(errs...)
}

func NewGroup(group *models.Group, app *App) (*Group, error) {
	return &Group{
		Group: group,
		app:   app,
	}, nil
}
