//go:build freebsd
// +build freebsd

package sys

import (
    "os/exec"
    "strconv"
    "strings"
)

func GetTCPCount() (int, error) {
    out, err := exec.Command("netstat", "-an", "-p", "tcp").Output()
    if err != nil {
        return 0, err
    }
    lines := strings.Split(string(out), "\n")
    return len(lines) - 2, nil // 减去头部和尾部空行
}

func GetUDPCount() (int, error) {
    out, err := exec.Command("netstat", "-an", "-p", "udp").Output()
    if err != nil {
        return 0, err
    }
    lines := strings.Split(string(out), "\n")
    return len(lines) - 2, nil // 减去头部和尾部空行
}
