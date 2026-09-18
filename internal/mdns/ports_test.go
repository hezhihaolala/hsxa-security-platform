package mdns

import "testing"

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []uint16
		wantErr bool
	}{
		{name: "single", input: "443", want: []uint16{443}},
		{name: "comma and ranges", input: "80,443,5000-5002,6000-6001", want: []uint16{80, 443, 5000, 5001, 5002, 6000, 6001}},
		{name: "deduplicates", input: "80,80-81", want: []uint16{80, 81}},
		{name: "zero", input: "0", wantErr: true},
		{name: "too large", input: "65536", wantErr: true},
		{name: "descending", input: "90-80", wantErr: true},
		{name: "malformed", input: "1-2-3", wantErr: true},
		{name: "empty", input: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePorts(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePorts() error = %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d ports; want %d", len(got), len(tt.want))
			}
			for _, port := range tt.want {
				if !got.Contains(port) {
					t.Errorf("missing port %d", port)
				}
			}
		})
	}
}
