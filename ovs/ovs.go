package ovs

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/docker/libnetwork/netutils"
	"github.com/vishvananda/netlink"
)

var (
	ipPath            string
	ovsPath           string
	ErrOvsctlNotFound = errors.New("ovs-vsctl not found")
	ErrIPCmdNotFound  = errors.New("ip cmd not found")
)

func initCheck() error {
	path, err := exec.LookPath("ovs-vsctl")
	if err != nil {
		return ErrOvsctlNotFound
	}
	ovsPath = path

	ipPath, err = exec.LookPath("ip")
	if err != nil {
		return ErrIPCmdNotFound
	}

	return nil
}

func ovsCmd(args ...string) (out string, err error) {
	if err := initCheck(); err != nil {
		return out, err
	}

	output, err := exec.Command(ovsPath, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("ovs-vsctl failed: ovs-vsctl %v: %s (%s)", strings.Join(args, " "), output, err)
	}

	return string(output), nil
}

// Execute a command in a network namespace pid
func NetNSExec(pid int, args ...string) (out string, err error) {
	if err := initCheck(); err != nil {
		return out, err
	}

	args = append([]string{"netns", "exec", strconv.Itoa(pid)}, args...)
	output, err := exec.Command(ipPath, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("ip netns exec failed: ip %v: %s (%s)", strings.Join(args, " "), output, err)
	}

	return string(output), nil
}

// creates a veth pair and adds it to a bridge
func CreateVethPair(iface string) (local string, guest string, err error) {
	var (
		vethPrefix = "veth"
		vethLen    = 7
	)

	// get the link of the iface we passed so we can use its MTU
	brLink, err := netlink.LinkByName(iface)
	if err != nil {
		return "", "", fmt.Errorf("finding link with name %s failed: %v", iface, err)
	}

	local, err = netutils.GenerateIfaceName(vethPrefix, vethLen)
	if err != nil {
		return "", "", fmt.Errorf("error generating veth name: %v", err)
	}

	guest, err = netutils.GenerateIfaceName(vethPrefix, vethLen)
	if err != nil {
		return "", "", fmt.Errorf("error generating veth name: %v", err)
	}

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: local, TxQLen: 0, MTU: brLink.Attrs().MTU},
		PeerName:  guest}
	if err := netlink.LinkAdd(veth); err != nil {
		return "", "", fmt.Errorf("error creating veth pair: %v", err)
	}

	exists, err := portExists(iface, local)
	if err != nil {
		return "", "", err
	}

	if !exists {
		if err := portAdd(iface, local); err != nil {
			return "", "", err
		}
	}

	return local, guest, nil
}

func BridgeExists(ifname string) (bool, error) {
	brOutput, err := ovsCmd("list-br")
	if err != nil {
		return false, err
	}

	if strings.Contains(brOutput, ifname) {
		return true, nil
	}

	return false, nil
}

func BridgeCreate(ifname string) error {
	_, err := ovsCmd("add-br", ifname)
	return err
}

func portExists(ifname, port string) (bool, error) {
	portOutput, err := ovsCmd("list-ports", ifname)
	if err != nil {
		return false, err
	}

	if strings.Contains(portOutput, port) {
		return true, nil
	}

	return false, nil
}

func portAdd(ifname, port string) error {
	_, err := ovsCmd("add-port", ifname, port)
	return err
}
