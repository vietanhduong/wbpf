package utils

import "testing"

func Test_IsNil(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		var a *int
		if !IsNil(a) {
			t.Error("should be nil")
		}
	})
	t.Run("not nil", func(t *testing.T) {
		type test struct{}
		var a test
		if IsNil(&a) {
			t.Error("should not be nil")
		}
	})
}

func Test_IsZero(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		var a *int
		if !IsZero(a) {
			t.Error("should be zero")
		}
	})
	t.Run("not nil", func(t *testing.T) {
		a := 1
		if IsZero(a) {
			t.Error("should not be zero")
		}
	})
	t.Run("zero", func(t *testing.T) {
		a := 0
		if !IsZero(a) {
			t.Error("should be zero")
		}
	})
	t.Run("not nil with struct", func(t *testing.T) {
		type test struct{ val int }
		var a test
		if !IsZero(a) {
			t.Error("should be zero")
		}
		a.val = 1
		if IsZero(a) {
			t.Error("should not be zero")
		}
	})
}
