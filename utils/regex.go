package utils

const (
	ValuePatternRegexStr  = `^\((?P<directions>(r|w|d)+)\)(?P<target>(VALUES|IDENTITY|SYSTEM))(?P<pattern>(\.([\w\-]+|[>\*]{1}))+)$`
	ValuesPatternRegexStr = `^(VALUES|IDENTITY|SYSTEM)(\.[\w\-]+)+$`
)
