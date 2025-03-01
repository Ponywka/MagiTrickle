package v1

import (
	"fmt"
	"net/http"
	"strconv"

	"magitrickle/api/types"
	"magitrickle/internal/app"
	"magitrickle/models"

	"github.com/rs/zerolog/log"
)

type Handler struct {
	app *app.App
}

func NewHandler(a *app.App) *Handler {
	return &Handler{app: a}
}

func (h *Handler) NetfilterDHook(w http.ResponseWriter, r *http.Request) {
	req, err := ReadJson[types.NetfilterDHookReq](r)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	log.Debug().Str("type", req.Type).Str("table", req.Table).Msg("netfilter.d event")
	if h.app.DnsOverrider() != nil {
		if err := h.app.DnsOverrider().NetfilterDHook(req.Type, req.Table); err != nil {
			log.Error().Err(err).Msg("error fixing iptables after netfilter.d")
		}
	}
	for _, group := range h.app.Groups() {
		if err := group.NetfilterDHook(req.Type, req.Table); err != nil {
			log.Error().Err(err).Msg("error while fixing iptables in group")
		}
	}
}

func (h *Handler) ListInterfaces(w http.ResponseWriter, r *http.Request) {
	interfaces, err := h.app.ListInterfaces()
	if err != nil {
		WriteError(w, http.StatusInternalServerError, fmt.Errorf("failed to get interfaces: %w", err).Error())
		return
	}
	res := make([]types.InterfaceRes, len(interfaces))
	for i, iface := range interfaces {
		res[i] = types.InterfaceRes{ID: iface.Name}
	}
	WriteJson(w, http.StatusOK, types.InterfacesRes{Interfaces: res})
}

func (h *Handler) SaveConfig(w http.ResponseWriter, r *http.Request) {
	if err := h.app.SaveConfig(); err != nil {
		WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save config: %v", err))
	}
}

func (h *Handler) GetGroups(w http.ResponseWriter, r *http.Request) {
	withRules := r.URL.Query().Get("with_rules") == "true"
	appGroups := h.app.Groups()
	modelGroups := make([]*models.Group, len(appGroups))
	for i, g := range appGroups {
		modelGroups[i] = g.Group
	}
	WriteJson(w, http.StatusOK, ToGroupsRes(modelGroups, withRules))
}

func (h *Handler) PutGroups(w http.ResponseWriter, r *http.Request) {
	req, err := ReadJson[types.GroupsReq](r)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Groups == nil {
		WriteError(w, http.StatusBadRequest, "no groups in request")
		return
	}
	for _, g := range h.app.Groups() {
		_ = g.Disable()
	}
	newGroups := make([]*models.Group, len(*req.Groups))
	for i, gReq := range *req.Groups {
		var existing *models.Group
		for _, g := range h.app.Groups() {
			if gReq.ID != nil && g.Group.ID == *gReq.ID {
				existing = g.Group
				break
			}
		}
		newGroups[i], err = FromGroupReq(gReq, existing)
		if err != nil {
			WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	h.app.ClearGroups()
	for _, grp := range newGroups {
		if err := h.app.AddGroup(grp); err != nil {
			WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	WriteJson(w, http.StatusOK, ToGroupsRes(newGroups, true))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

func (h *Handler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	req, err := ReadJson[types.GroupReq](r)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	group, err := FromGroupReq(req, nil)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.app.AddGroup(group); err != nil {
		WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	WriteJson(w, http.StatusOK, ToGroupRes(group, true))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

func (h *Handler) GetGroup(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	withRules := r.URL.Query().Get("with_rules") == "true"
	group := h.app.Groups()[groupIdx].Group
	WriteJson(w, http.StatusOK, ToGroupRes(group, withRules))
}

func (h *Handler) PutGroup(w http.ResponseWriter, r *http.Request) {
	req, err := ReadJson[types.GroupReq](r)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := h.app.Groups()[groupIdx]

	enabled := groupWrapper.Enabled()
	if enabled {
		if err := groupWrapper.Disable(); err != nil {
			WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to disable group: %v", err))
			return
		}
	}

	updatedGroup, err := FromGroupReq(req, groupWrapper.Group)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	if enabled {
		if err := groupWrapper.Enable(); err != nil {
			WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to enable group: %v", err))
			return
		}
		if err := groupWrapper.Sync(); err != nil {
			WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sync group: %v", err))
			return
		}
	}
	WriteJson(w, http.StatusOK, ToGroupRes(updatedGroup, true))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

func (h *Handler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := h.app.Groups()[groupIdx]
	if groupWrapper.Enabled() {
		if err := groupWrapper.Disable(); err != nil {
			WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to disable group: %v", err))
			return
		}
	}
	h.app.RemoveGroupByIndex(groupIdx)
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

func (h *Handler) GetRules(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	rules := h.app.Groups()[groupIdx].Group.Rules
	WriteJson(w, http.StatusOK, ToRulesRes(rules))
}

func (h *Handler) PutRules(w http.ResponseWriter, r *http.Request) {
	req, err := ReadJson[types.RulesReq](r)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Rules == nil {
		WriteError(w, http.StatusBadRequest, "no rules in request")
		return
	}
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := h.app.Groups()[groupIdx]
	enabled := groupWrapper.Enabled()

	newRules := make([]*models.Rule, len(*req.Rules))
	for i, rr := range *req.Rules {
		id := types.RandomID()
		if rr.ID != nil {
			found := false
			for _, oldRule := range groupWrapper.Group.Rules {
				if oldRule.ID == *rr.ID {
					id = *rr.ID
					found = true
					break
				}
			}
			if !found {
				WriteError(w, http.StatusNotFound, "rule not found")
				return
			}
		}
		newRules[i] = &models.Rule{
			ID:     id,
			Name:   rr.Name,
			Type:   rr.Type,
			Rule:   rr.Rule,
			Enable: rr.Enable,
		}
	}
	groupWrapper.Group.Rules = newRules
	if enabled {
		if err := groupWrapper.Sync(); err != nil {
			WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sync group: %v", err))
			return
		}
	}
	WriteJson(w, http.StatusOK, ToRulesRes(newRules))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

func (h *Handler) CreateRule(w http.ResponseWriter, r *http.Request) {
	req, err := ReadJson[types.RuleReq](r)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := h.app.Groups()[groupIdx]
	enabled := groupWrapper.Enabled()

	rule, err := FromRuleReq(req, groupWrapper.Group.Rules)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	groupWrapper.Group.Rules = append(groupWrapper.Group.Rules, rule)
	if enabled {
		if err := groupWrapper.Sync(); err != nil {
			WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sync group: %v", err))
			return
		}
	}
	WriteJson(w, http.StatusOK, ToRuleRes(rule))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

func (h *Handler) GetRule(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	ruleIdx, _ := strconv.Atoi(r.Header.Get("ruleIdx"))
	rule := h.app.Groups()[groupIdx].Group.Rules[ruleIdx]
	WriteJson(w, http.StatusOK, ToRuleRes(rule))
}

func (h *Handler) PutRule(w http.ResponseWriter, r *http.Request) {
	req, err := ReadJson[types.RuleReq](r)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := h.app.Groups()[groupIdx]
	enabled := groupWrapper.Enabled()

	ruleIdx, _ := strconv.Atoi(r.Header.Get("ruleIdx"))
	rule := groupWrapper.Group.Rules[ruleIdx]
	rule.Name = req.Name
	rule.Type = req.Type
	rule.Rule = req.Rule
	rule.Enable = req.Enable

	if enabled {
		if err := groupWrapper.Sync(); err != nil {
			WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sync group: %v", err))
			return
		}
	}
	WriteJson(w, http.StatusOK, ToRuleRes(rule))
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}

func (h *Handler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	groupIdx, _ := strconv.Atoi(r.Header.Get("groupIdx"))
	groupWrapper := h.app.Groups()[groupIdx]
	enabled := groupWrapper.Enabled()

	ruleIdx, _ := strconv.Atoi(r.Header.Get("ruleIdx"))
	groupWrapper.Group.Rules = append(groupWrapper.Group.Rules[:ruleIdx], groupWrapper.Group.Rules[ruleIdx+1:]...)
	if enabled {
		if err := groupWrapper.Sync(); err != nil {
			WriteError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sync group: %v", err))
			return
		}
	}
	if r.URL.Query().Get("save") == "true" {
		if err := h.app.SaveConfig(); err != nil {
			log.Error().Err(err).Msg("failed to save config file")
		}
	}
}
