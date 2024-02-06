package byteorder

import "testing"

func TestByteOrder(t *testing.T) {
	byteOrder = determineHostByteOrder()
	bo := GetHostByteOrder()
	if bo == nil {
		t.Fatal("GetHostByteOrder() returned nil")
	}
}
