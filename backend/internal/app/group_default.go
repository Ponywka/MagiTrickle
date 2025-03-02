//go:build !kn

package app

func (g *Group) routerSpecificPatches(iptType, table string) error {
	return nil
}
