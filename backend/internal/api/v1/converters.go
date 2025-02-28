package v1

import (
	"fmt"
	"regexp"

	"magitrickle/api/types"
	"magitrickle/models"
)

var colorRegExp = regexp.MustCompile(`^#[0-9a-f]{6}$`)

func FromGroupReq(req types.GroupReq, existing *models.Group) (*models.Group, error) {
	var group *models.Group
	if existing == nil {
		group = &models.Group{ID: types.RandomID()}
	} else {
		group = existing
	}
	if req.ID != nil {
		if existing != nil && group.ID != *req.ID {
			return nil, fmt.Errorf("group ID mismatch")
		}
		if existing == nil {
			group.ID = *req.ID
		}
	}
	group.Name = req.Name
	if !colorRegExp.MatchString(req.Color) {
		req.Color = "#ffffff"
	}
	group.Color = req.Color
	group.Interface = req.Interface
	group.Enable = true
	// TODO: Make required after 1.0.0
	if req.Enable != nil {
		group.Enable = *req.Enable
	}
	if req.Rules != nil {
		newRules := make([]*models.Rule, len(*req.Rules))
		for i, ruleReq := range *req.Rules {
			r, err := FromRuleReq(ruleReq, group.Rules)
			if err != nil {
				return nil, err
			}
			newRules[i] = r
		}
		group.Rules = newRules
	}
	return group, nil
}

func FromRuleReq(ruleReq types.RuleReq, existingRules []*models.Rule) (*models.Rule, error) {
	var rule *models.Rule
	if ruleReq.ID != nil {
		for _, r := range existingRules {
			if r.ID == *ruleReq.ID {
				rule = r
				break
			}
		}
	}
	if rule == nil {
		rule = &models.Rule{ID: types.RandomID()}
	}
	rule.Name = ruleReq.Name
	rule.Type = ruleReq.Type
	rule.Rule = ruleReq.Rule
	rule.Enable = ruleReq.Enable
	return rule, nil
}

func ToGroupsRes(groups []*models.Group, withRules bool) types.GroupsRes {
	l := make([]types.GroupRes, len(groups))
	for i, g := range groups {
		l[i] = ToGroupRes(g, withRules)
	}
	return types.GroupsRes{Groups: &l}
}

func ToGroupRes(g *models.Group, withRules bool) types.GroupRes {
	res := types.GroupRes{
		ID:        g.ID,
		Name:      g.Name,
		Color:     g.Color,
		Interface: g.Interface,
		Enable:    g.Enable,
	}
	if withRules {
		res.RulesRes = ToRulesRes(g.Rules)
	}
	return res
}

func ToRulesRes(rules []*models.Rule) types.RulesRes {
	l := make([]types.RuleRes, len(rules))
	for i, r := range rules {
		l[i] = ToRuleRes(r)
	}
	return types.RulesRes{Rules: &l}
}

func ToRuleRes(r *models.Rule) types.RuleRes {
	return types.RuleRes{
		ID:     r.ID,
		Name:   r.Name,
		Type:   r.Type,
		Rule:   r.Rule,
		Enable: r.Enable,
	}
}
