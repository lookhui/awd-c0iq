package apperrors

import "fmt"

type AppError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Err     error          `json:"-"`
	Details map[string]any `json:"details,omitempty"`
}

func (e *AppError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Err == nil {
		return e.Message
	}
	return fmt.Sprintf("%s: %v", e.Message, e.Err)
}

func (e *AppError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *AppError) WithDetails(details map[string]any) *AppError {
	e.Details = details
	return e
}

func NewInvalidInputError(message string, err error) *AppError {
	return &AppError{Code: "invalid_input", Message: message, Err: err}
}

func NewFileError(message string, err error) *AppError {
	return &AppError{Code: "file_error", Message: message, Err: err}
}
