package utils

import "reflect"

func IsZero(val any) bool {
	rv := reflect.ValueOf(val)
	return !rv.IsValid() || reflect.ValueOf(val).IsZero()
}

func IsNil(val any) bool {
	rv := reflect.ValueOf(val)
	return !rv.IsValid() || rv.IsNil()
}
