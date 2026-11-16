//go:build ndpi && cgo

package flow

/*
#cgo CFLAGS: -I/usr/include/ndpi -I/usr/local/include/ndpi
#cgo LDFLAGS: -lndpi -lm -lpthread
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if __has_include(<ndpi/ndpi_api.h>)
#include <ndpi/ndpi_api.h>
#elif __has_include(<libndpi/ndpi_api.h>)
#include <libndpi/ndpi_api.h>
#else
#include <ndpi_api.h>
#endif

#if !defined(NDPI_MAJOR) || NDPI_MAJOR < 5
#error "x2kafka requires nDPI >= 5.0"
#endif

// Confidence classes returned to Go (must match AppConfidence).
#define X2K_APP_UNKNOWN 0
#define X2K_APP_BY_PORT 1
#define X2K_APP_BY_IP   2
#define X2K_APP_BY_DPI  3

static struct ndpi_detection_module_struct *x2k_ndpi_init(void) {
    struct ndpi_detection_module_struct *mod;
#if NDPI_MAJOR >= 6
    mod = ndpi_init_detection_module(NULL, NDPI_LICENSE_NOT_FOR_PROFIT_LGPL);
#else
    mod = ndpi_init_detection_module(NULL);
#endif
    if (!mod) return NULL;
    if (ndpi_finalize_initialization(mod) != 0) {
        ndpi_exit_detection_module(mod);
        return NULL;
    }
    return mod;
}

static void x2k_ndpi_exit(struct ndpi_detection_module_struct *mod) {
    if (mod) ndpi_exit_detection_module(mod);
}

static int x2k_confidence_class(ndpi_confidence_t c) {
    switch (c) {
    case NDPI_CONFIDENCE_UNKNOWN:
        return X2K_APP_UNKNOWN;
    case NDPI_CONFIDENCE_MATCH_BY_PORT:
        return X2K_APP_BY_PORT;
    case NDPI_CONFIDENCE_MATCH_BY_IP:
        return X2K_APP_BY_IP;
    default:
        return X2K_APP_BY_DPI;
    }
}

// Classifies one isolated packet: sFlow samples are random packets of a flow, so no
// per-flow state is kept. When the packet alone is not enough, ndpi_detection_giveup()
// returns nDPI's best guess (by IP range or by port).
static const char *x2k_ndpi_classify(struct ndpi_detection_module_struct *mod,
                                     const uint8_t *data, uint16_t len, uint64_t ts_ms,
                                     uint16_t *id_out, int *confidence_out) {
    struct ndpi_flow_struct *flow;
    ndpi_protocol proto;
    uint16_t pid;
    const char *name;

    *id_out = 0;
    *confidence_out = X2K_APP_UNKNOWN;
    if (!mod || !data || len == 0) return "";

    flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
    if (!flow) return "";
    memset(flow, 0, SIZEOF_FLOW_STRUCT);

    proto = ndpi_detection_process_packet(mod, flow, data, len, ts_ms, NULL);
    if (proto.proto.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
        proto.proto.master_protocol == NDPI_PROTOCOL_UNKNOWN) {
        proto = ndpi_detection_giveup(mod, flow);
    }

    pid = proto.proto.app_protocol;
    if (pid == NDPI_PROTOCOL_UNKNOWN) pid = proto.proto.master_protocol;

    name = "";
    if (pid != NDPI_PROTOCOL_UNKNOWN) {
        // Owned by the detection module, valid until x2k_ndpi_exit().
        name = ndpi_get_proto_name(mod, pid);
        if (!name) name = "";
        *id_out = pid;
        *confidence_out = x2k_confidence_class(flow->confidence);
        if (*confidence_out == X2K_APP_UNKNOWN) *confidence_out = X2K_APP_BY_PORT;
    }

    // ndpi_flow_free() also releases the flow's dynamic members; calling
    // ndpi_free_flow_data() before it frees them twice.
    ndpi_flow_free(flow);
    return name;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// NDPIStatus reports whether this binary was built with nDPI support.
func NDPIStatus() (enabled bool, details string) {
	return true, fmt.Sprintf("enabled (libndpi %s)", C.GoString(C.ndpi_revision()))
}

type ndpiClassifier struct {
	mod *C.struct_ndpi_detection_module_struct
}

// NewNDPIClassifier creates an nDPI detection module. It must be released with Close.
func NewNDPIClassifier() (AppClassifier, error) {
	mod := C.x2k_ndpi_init()
	if mod == nil {
		return nil, errors.New("failed to initialize the nDPI detection module")
	}
	return &ndpiClassifier{mod: mod}, nil
}

func (c *ndpiClassifier) Classify(l3 []byte, tsMillis int64) AppMatch {
	if c.mod == nil || len(l3) == 0 {
		return AppMatch{}
	}
	if len(l3) > 0xFFFF {
		l3 = l3[:0xFFFF]
	}

	var id C.uint16_t
	var confidence C.int
	name := C.x2k_ndpi_classify(c.mod, (*C.uint8_t)(unsafe.Pointer(&l3[0])), C.uint16_t(len(l3)),
		C.uint64_t(tsMillis), &id, &confidence)

	m := AppMatch{
		Name:       C.GoString(name),
		ID:         uint16(id),
		Confidence: AppConfidence(confidence),
	}
	if m.Name == "" || m.Name == "Unknown" {
		return AppMatch{}
	}
	return m
}

func (c *ndpiClassifier) Close() {
	if c.mod != nil {
		C.x2k_ndpi_exit(c.mod)
		c.mod = nil
	}
}
