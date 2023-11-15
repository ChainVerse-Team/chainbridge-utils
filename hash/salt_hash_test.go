package hash

import (
	"reflect"
	"testing"
)

func Test_hashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password []byte
		want     []byte
		wantErr  bool
	}{
		{
			name:     "correst testcase 1",
			password: []byte("Helloworld"),
			want:     []byte{148, 188, 171, 220, 198, 43, 16, 33, 202, 188, 177, 135, 187, 100, 166, 52, 231, 192, 181, 134, 158, 242, 58, 5, 252, 148, 159, 180, 252, 137, 71, 182},
			wantErr:  false,
		},
		{
			name:     "correst testcase 2",
			password: []byte("123456"),
			want:     []byte{67, 142, 104, 21, 71, 216, 191, 8, 88, 159, 190, 241, 66, 48, 97, 230, 90, 46, 148, 77, 163, 166, 53, 255, 213, 76, 217, 30, 51, 109, 184, 8},
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hashPassword(tt.password)
			t.Log(string(got))
			if (err != nil) != tt.wantErr {
				t.Errorf("hashPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("hashPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_xorBytes(t *testing.T) {
	tests := []struct {
		name    string
		a       []byte
		b       []byte
		want    []byte
		wantErr bool
	}{
		{
			name: "different bytes length",
			a: []byte{1,2,3,4},
			b: []byte("helloworld"),
			want: nil,
			wantErr: true,
		},
		{
			name: "same bytes length",
			a: []byte{1, 2, 3, 4},
			b: []byte{7, 8, 9, 10},
			want: []byte{6, 10, 10, 14},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := xorBytes(tt.a, tt.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("xorBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("xorBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}
