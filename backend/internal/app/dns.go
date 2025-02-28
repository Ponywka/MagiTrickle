package app

import (
	"context"
	"fmt"
	"net"
	"time"

	dnsMitmProxy "magitrickle/dns-mitm-proxy"
	"magitrickle/records"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

func (a *App) initDNSMITM() {
	a.dnsMITM = &dnsMitmProxy.DNSMITMProxy{
		UpstreamDNSAddress: a.config.DNSProxy.Upstream.Address,
		UpstreamDNSPort:    a.config.DNSProxy.Upstream.Port,
		RequestHook:        a.dnsRequestHook,
		ResponseHook:       a.dnsResponseHook,
	}
	a.records = records.New()
}

func (a *App) startDNSListeners(ctx context.Context, errChan chan error) {
	go func() {
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", a.config.DNSProxy.Host.Address, a.config.DNSProxy.Host.Port))
		if err != nil {
			errChan <- fmt.Errorf("failed to resolve udp address: %v", err)
			return
		}
		if err = a.dnsMITM.ListenUDP(ctx, addr); err != nil {
			errChan <- fmt.Errorf("failed to serve DNS UDP proxy: %v", err)
		}
	}()
	go func() {
		addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", a.config.DNSProxy.Host.Address, a.config.DNSProxy.Host.Port))
		if err != nil {
			errChan <- fmt.Errorf("failed to resolve tcp address: %v", err)
			return
		}
		if err = a.dnsMITM.ListenTCP(ctx, addr); err != nil {
			errChan <- fmt.Errorf("failed to serve DNS TCP proxy: %v", err)
		}
	}()
}

func (a *App) dnsRequestHook(clientAddr net.Addr, reqMsg dns.Msg, network string) (*dns.Msg, *dns.Msg, error) {
	var clientAddrStr string
	if clientAddr != nil {
		clientAddrStr = clientAddr.String()
	}
	for _, q := range reqMsg.Question {
		log.Trace().
			Str("name", q.Name).
			Int("qtype", int(q.Qtype)).
			Int("qclass", int(q.Qclass)).
			Str("clientAddr", clientAddrStr).
			Str("network", network).
			Msg("requested record")
	}
	if a.config.DNSProxy.DisableFakePTR {
		return nil, nil, nil
	}
	if len(reqMsg.Question) == 1 && reqMsg.Question[0].Qtype == dns.TypePTR {
		respMsg := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:                 reqMsg.Id,
				Response:           true,
				RecursionAvailable: true,
				Rcode:              dns.RcodeNameError,
			},
			Question: reqMsg.Question,
		}
		return nil, respMsg, nil
	}
	return nil, nil, nil
}

func (a *App) dnsResponseHook(clientAddr net.Addr, reqMsg dns.Msg, respMsg dns.Msg, network string) (*dns.Msg, error) {
	defer a.handleMessage(respMsg, clientAddr, &network)
	if a.config.DNSProxy.DisableDropAAAA {
		return nil, nil
	}
	var filteredAnswers []dns.RR
	for _, ans := range respMsg.Answer {
		if ans.Header().Rrtype != dns.TypeAAAA {
			filteredAnswers = append(filteredAnswers, ans)
		}
	}
	respMsg.Answer = filteredAnswers
	return &respMsg, nil
}

func (a *App) handleMessage(msg dns.Msg, clientAddr net.Addr, network *string) {
	for _, rr := range msg.Answer {
		a.handleRecord(rr, clientAddr, network)
	}
}

func (a *App) handleRecord(rr dns.RR, clientAddr net.Addr, network *string) {
	switch v := rr.(type) {
	case *dns.A:
		a.processARecord(*v, clientAddr, network)
	case *dns.CNAME:
		a.processCNameRecord(*v, clientAddr, network)
	}
}

func (a *App) processARecord(aRecord dns.A, clientAddr net.Addr, network *string) {
	var clientAddrStr, networkStr string
	if clientAddr != nil {
		clientAddrStr = clientAddr.String()
	}
	if network != nil {
		networkStr = *network
	}
	log.Trace().
		Str("name", aRecord.Hdr.Name).
		Str("address", aRecord.A.String()).
		Int("ttl", int(aRecord.Hdr.Ttl)).
		Str("clientAddr", clientAddrStr).
		Str("network", networkStr).
		Msg("processing A record")
	ttlDuration := aRecord.Hdr.Ttl + a.config.Netfilter.IPSet.AdditionalTTL
	name := aRecord.Hdr.Name[:len(aRecord.Hdr.Name)-1]
	a.records.AddARecord(name, aRecord.A, ttlDuration)
	names := a.records.GetAliases(name)
	for _, group := range a.groups {
	RuleLoop:
		for _, domain := range group.Rules {
			if !domain.IsEnabled() {
				continue
			}
			for _, n := range names {
				if !domain.IsMatch(n) {
					continue
				}
				if err := group.AddIP(aRecord.A, ttlDuration); err != nil {
					log.Error().Err(err).Msg("failed to add IP")
				} else {
					log.Debug().Str("address", aRecord.A.String()).Msg("added IP")
				}
				break RuleLoop
			}
		}
	}
}

func (a *App) processCNameRecord(cn dns.CNAME, clientAddr net.Addr, network *string) {
	var clientAddrStr, networkStr string
	if clientAddr != nil {
		clientAddrStr = clientAddr.String()
	}
	if network != nil {
		networkStr = *network
	}
	log.Trace().
		Str("name", cn.Hdr.Name).
		Str("cname", cn.Target).
		Int("ttl", int(cn.Hdr.Ttl)).
		Str("clientAddr", clientAddrStr).
		Str("network", networkStr).
		Msg("processing CNAME record")
	ttlDuration := cn.Hdr.Ttl + a.config.Netfilter.IPSet.AdditionalTTL
	name := cn.Hdr.Name[:len(cn.Hdr.Name)-1]
	target := cn.Target[:len(cn.Target)-1]
	a.records.AddCNameRecord(name, target, ttlDuration)
	now := time.Now()
	aRecords := a.records.GetARecords(name)
	names := a.records.GetAliases(name)
	for _, group := range a.groups {
	RuleLoop:
		for _, domain := range group.Rules {
			if !domain.IsEnabled() {
				continue
			}
			for _, n := range names {
				if !domain.IsMatch(n) {
					continue
				}
				for _, aRec := range aRecords {
					ttl := uint32(now.Sub(aRec.Deadline).Seconds())
					if err := group.AddIP(aRec.Address, ttl); err != nil {
						log.Error().Err(err).Msg("failed to add IP from CNAME")
					}
				}
				break RuleLoop
			}
		}
	}
}
