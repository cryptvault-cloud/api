package client

import (
	"fmt"
	"regexp"
)

var ValuePatternRegex *regexp.Regexp
var ValuesPatternRegex *regexp.Regexp

const ValuePatternRegexStr = `^\((?P<directions>(r|w|d)+)\)(?P<target>(VALUES|IDENTITY|SYSTEM))(?P<pattern>(\.[a-z0-9_\->\*]+)+)$`
const ValuesPatternRegexStr = `^(VALUES|IDENTITY|SYSTEM)(\.[a-z0-9_\-]+)+$`

func init() {
	ValuePatternRegex = regexp.MustCompile(ValuePatternRegexStr)
	ValuesPatternRegex = regexp.MustCompile(ValuesPatternRegexStr)
}

type RightDescription struct {
	Target     RightTarget
	Right      Directions
	RightValue string
}

func GetRightDescriptionByString(valuePattern string) ([]RightDescription, error) {
	if !ValuePatternRegex.MatchString(valuePattern) {
		return nil, fmt.Errorf("valuePattern does not match %s", ValuePatternRegexStr)
	}
	var direction, target, pattern []byte

	for _, submatches := range ValuePatternRegex.FindAllStringSubmatchIndex(valuePattern, -1) {
		direction = ValuePatternRegex.ExpandString(direction, "$directions", valuePattern, submatches)
		target = ValuePatternRegex.ExpandString(target, "$target", valuePattern, submatches)
		pattern = ValuePatternRegex.ExpandString(pattern, "$pattern", valuePattern, submatches)
	}

	if len(string(direction)) > 3 {
		return nil, fmt.Errorf("direction can max be rwd")
	}
	var result []RightDescription

	for _, v := range string(direction) {
		var right Directions
		switch v {
		case 'r':
			right = DirectionsRead
		case 'w':
			right = DirectionsWrite
		case 'd':
			right = DirectionsDelete
		}
		var t RightTarget
		switch string(target) {
		case "VALUES":
			t = RightTargetValues
		case "IDENTITY":
			t = RightTargetIdentities
		case "SYSTEM":
			t = RightTargetSystem
		}

		result = append(result, RightDescription{
			Right:      right,
			Target:     t,
			RightValue: fmt.Sprintf("%s%s", string(target), pattern),
		})
	}
	return result, nil
}
