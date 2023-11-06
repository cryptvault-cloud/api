package api

import (
	"reflect"
	"testing"
)

func TestGetRightDescriptionByString(t *testing.T) {
	type args struct {
	}
	tests := []struct {
		name              string
		inputValuePattern string
		want              []RightDescription
		wantErr           bool
	}{
		{
			name:              "Simple happy path test",
			inputValuePattern: "(rwd)VALUES.a.b.c",
			want: []RightDescription{
				{
					Target:     RightTargetValues,
					Right:      DirectionsRead,
					RightValue: "VALUES.a.b.c",
				},
				{
					Target:     RightTargetValues,
					Right:      DirectionsWrite,
					RightValue: "VALUES.a.b.c",
				},
				{
					Target:     RightTargetValues,
					Right:      DirectionsDelete,
					RightValue: "VALUES.a.b.c",
				},
			},
		},
		{
			name:              "only read",
			inputValuePattern: "(r)VALUES.a.b.c",
			want: []RightDescription{
				{
					Target:     RightTargetValues,
					Right:      DirectionsRead,
					RightValue: "VALUES.a.b.c",
				},
			},
		},
		{
			name:              "Identity rigth with deep wildcard",
			inputValuePattern: "(r)IDENTITY.a.b.>",
			want: []RightDescription{
				{
					Target:     RightTargetIdentities,
					Right:      DirectionsRead,
					RightValue: "IDENTITY.a.b.>",
				},
			},
		},
		{
			name:              "Identity rigth with same area wildcard",
			inputValuePattern: "(rwd)IDENTITY.a.b.*",
			want: []RightDescription{
				{
					Target:     RightTargetIdentities,
					Right:      DirectionsRead,
					RightValue: "IDENTITY.a.b.*",
				},
				{
					Target:     RightTargetIdentities,
					Right:      DirectionsWrite,
					RightValue: "IDENTITY.a.b.*",
				},
				{
					Target:     RightTargetIdentities,
					Right:      DirectionsDelete,
					RightValue: "IDENTITY.a.b.*",
				},
			},
		},
		{
			name:              "Invalid input1",
			inputValuePattern: "(r)IDENTITY.a.b.>*",
			wantErr:           true,
		},
		{
			name:              "Invalid input2",
			inputValuePattern: "IDENTITY.a.b.>",
			wantErr:           true,
		},
		{
			name:              "Invalid input3",
			inputValuePattern: "IDENTITIES.a.b.>",
			wantErr:           true,
		},
		{
			name:              "Invalid input4",
			inputValuePattern: "VALUE.a.b.>",
			wantErr:           true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetRightDescriptionByString(tt.inputValuePattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRightDescriptionByString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetRightDescriptionByString() = %v, want %v", got, tt.want)
			}
		})
	}
}
