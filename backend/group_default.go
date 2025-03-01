//go:build !kn

package magitrickle

func (g *Group) routerSpecificPatches(iptType, table string) error {
	return nil
}
