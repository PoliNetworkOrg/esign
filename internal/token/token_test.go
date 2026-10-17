package token

import (
	"errors"
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
