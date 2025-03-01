package models

import (
	"magitrickle/api/types"
)

type Group struct {
	ID        types.ID
	Name      string
	Color     string
	Interface string
	Enable    bool
	Rules     []*Rule
}
