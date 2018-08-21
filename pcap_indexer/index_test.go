package pcap_indexer

import (
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func TestIndex(t *testing.T) {
	f, err := ioutil.TempFile("", "index")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(f.Name())

	w := NewIndexWriter(f)
	w.WriteOffset(0)
	w.WriteOffset(10000)
	w.WriteOffset(12000)
	w.WriteOffset(12500)

	f.Close()

	rf, err := os.Open(f.Name())

	r := NewIndexReader(rf)

	expected := []uint32{0, 10000, 2000, 500}
	var found []uint32
	for {
		delta, err := r.ReadNextOffsetDelta()
		//t.Logf("%v: %v", delta)
		if err == io.EOF {
			break
		}
		found = append(found, delta)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(expected, found) {
		t.Fatalf("expected!=found: %v != %v", expected, found)
	}

}
