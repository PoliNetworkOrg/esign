package token

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestAfterPIN(t *testing.T) {
	if AfterPIN(nil) != nil {
		t.Fatal("nil")
	}
	orig := &Error{Code: CodePinIncorrect, RetriesLeft: 2, Err: errors.New("wrong")}
	err := AfterPIN(orig)
	var e *Error
	if !errors.As(err, &e) || !e.PINSent || e.Code != CodePinIncorrect || e.RetriesLeft != 2 || orig.PINSent {
		t.Fatalf("%+v", e)
	}
	if err := AfterPIN(errors.New("io")); !PINSent(err) || CodeOf(err) != CodeDevice {
		t.Fatalf("%v", err)
	}
	if PINSent(Errorf(CodeNotPaired, "x")) {
		t.Fatal("unmarked error reported as sent")
	}
}

type panicking struct{}

func (panicking) Name() string                                  { return "broken" }
func (panicking) Status(context.Context) Status                 { panic("index out of range") }
func (panicking) Open(context.Context, string) (Session, error) { return nil, nil }

func TestSafeStatus(t *testing.T) {
	st, err := SafeStatus(t.Context(), panicking{})
	if st.Available || st.Provider != "broken" || err == nil || !strings.Contains(err.Error(), "index out of range") {
		t.Fatalf("got %+v, %v", st, err)
	}
}
