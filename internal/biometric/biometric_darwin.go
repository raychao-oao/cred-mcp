//go:build darwin && cgo

package biometric

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework LocalAuthentication -framework Foundation

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

// Result codes returned to Go.
#define CRED_BIO_OK          0
#define CRED_BIO_CANCELLED   1
#define CRED_BIO_UNAVAILABLE 2
#define CRED_BIO_OTHER       3

// cred_mcp_biometric_unlock blocks until the user authenticates, cancels,
// or the OS rejects the request. Uses LAPolicyDeviceOwnerAuthentication so
// Touch ID failure / absence falls back to the system password automatically.
static int cred_mcp_biometric_unlock(const char *reason) {
    @autoreleasepool {
        LAContext *ctx = [[LAContext alloc] init];
        NSError *canErr = nil;
        if (![ctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&canErr]) {
            return CRED_BIO_UNAVAILABLE;
        }
        NSString *reasonStr = [NSString stringWithUTF8String:reason];
        __block int rc = CRED_BIO_OTHER;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        [ctx evaluatePolicy:LAPolicyDeviceOwnerAuthentication
            localizedReason:reasonStr
                      reply:^(BOOL success, NSError * _Nullable err) {
            if (success) {
                rc = CRED_BIO_OK;
            } else if (err != nil && (err.code == LAErrorUserCancel ||
                                       err.code == LAErrorAppCancel ||
                                       err.code == LAErrorSystemCancel)) {
                rc = CRED_BIO_CANCELLED;
            } else {
                rc = CRED_BIO_OTHER;
            }
            dispatch_semaphore_signal(sem);
        }];
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        return rc;
    }
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

const defaultReason = "cred-mcp wants to access your stashed secrets"

// Unlock presents a Touch ID / passcode prompt and blocks until the user
// resolves it. Returns nil on success, ErrCancelled if the user dismissed
// the prompt, ErrUnavailable if no biometric and no device passcode are
// available, or a wrapped error for other failure modes (e.g. lockout).
func Unlock() error {
	creason := C.CString(defaultReason)
	defer C.free(unsafe.Pointer(creason))

	switch rc := int(C.cred_mcp_biometric_unlock(creason)); rc {
	case 0:
		return nil
	case 1:
		return ErrCancelled
	case 2:
		return ErrUnavailable
	default:
		return fmt.Errorf("biometric: authentication failed (rc=%d)", rc)
	}
}
