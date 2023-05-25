package aws_signing_helper

import "testing"

func Test_bindAddrAllowed(t *testing.T) {
	type args struct {
		addr string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "open", args: args{addr: "0.0.0.0"}, want: false},
		{name: "localhost", args: args{addr: "127.0.0.1"}, want: true},
		{name: "loopback", args: args{addr: "127.0.0.1"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bindAddrAllowed(tt.args.addr); got != tt.want {
				t.Errorf("bindAddrAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}
