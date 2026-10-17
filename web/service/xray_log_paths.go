package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
)

// Apply at runtime generation, so raw edits and imported databases share the
// same confinement. Match keys as xray-core's encoding/json decoder does.
func resolveXrayLogPaths(raw json_util.RawMessage) (json_util.RawMessage, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return raw, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("invalid Xray log configuration: %w", err)
	}
	for _, canonical := range []string{"access", "error"} {
		matched := false
		for key, value := range fields {
			if !strings.EqualFold(key, canonical) {
				continue
			}
			if matched {
				return nil, fmt.Errorf("ambiguous Xray log key: %s", canonical)
			}
			matched = true
			var name string
			if string(value) == "null" {
				name = ""
			} else if err := json.Unmarshal(value, &name); err != nil {
				return nil, fmt.Errorf("invalid Xray %s log path", canonical)
			}
			confined, err := confineXrayLogPath(name)
			if err != nil {
				return nil, err
			}
			encoded, err := json.Marshal(confined)
			if err != nil {
				return nil, err
			}
			// Keep the key during iteration; canonicalize in a second pass below.
			fields[key] = encoded
		}
		for key, value := range fields {
			if key != canonical && strings.EqualFold(key, canonical) {
				delete(fields, key)
				fields[canonical] = value
			}
		}
	}
	out, err := json.Marshal(fields)
	return json_util.RawMessage(out), err
}

func confineXrayLogPath(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if strings.EqualFold(value, "none") {
		return "none", nil
	}
	// Interpret both separators regardless of the OS preparing the config.
	name := path.Base(strings.ReplaceAll(value, `\`, "/"))
	if name == "." || name == ".." || name == "/" || strings.ContainsAny(name, ":\x00") || strings.ContainsFunc(name, unicode.IsControl) || !filepath.IsLocal(name) {
		return "", fmt.Errorf("invalid Xray log filename")
	}
	dir, err := filepath.Abs(config.GetLogFolder())
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	target := filepath.Join(dir, name)
	// Xray reopens this path, so refuse symlinks and special files instead of
	// resolving an attacker-chosen file outside the log directory.
	info, err := os.Lstat(target)
	if err == nil && !info.Mode().IsRegular() {
		return "", fmt.Errorf("Xray log target must be a regular file")
	}
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return target, nil
}
