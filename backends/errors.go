package backends

import "errors"

var (
	// ErrWatchNotSupported is raised when trying to access watch feature from a watch disabled backend
	ErrWatchNotSupported = errors.New("backend: Watch prefix not supported for this backend")
	// ErrWatchCanceled is raised when trying to shutdown the backend storage
	ErrWatchCanceled = errors.New("backend: Watch canceled")
)
