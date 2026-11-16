//go:build !ndpi || !cgo

package flow

import "errors"

// NDPIStatus reports whether this binary was built with nDPI support.
func NDPIStatus() (enabled bool, details string) {
	return false, "disabled (built without the ndpi tag)"
}

// NewNDPIClassifier fails in builds without nDPI; callers fall back to port mapping.
func NewNDPIClassifier() (AppClassifier, error) {
	return nil, errors.New("x2kafka was built without nDPI support")
}
