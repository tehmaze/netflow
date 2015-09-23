package netflow

// https://www.iana.org/assignments/ipfix/ipfix-information-elements.csv

// https://www.iana.org/assignments/ipfix/ipfix-information-element-data-types.csv
type ipfixDataType struct {
	Name   string
	Length int
	String func(b []byte) string
}

var ipfixDataTypes = map[uint8]ipfixDataType{
	0:  ipfixDataType{"octetArray", -1, func(b []byte) string { return string(b) }},
	1:  ipfixDataType{"unsigned8", 1, nil},
	2:  ipfixDataType{"unsigned16", 2, nil},
	3:  ipfixDataType{"unsigned32", 4, nil},
	4:  ipfixDataType{"unsigned64", 8, nil},
	5:  ipfixDataType{"signed8", 1, nil},
	6:  ipfixDataType{"signed16", 2, nil},
	7:  ipfixDataType{"signed32", 4, nil},
	8:  ipfixDataType{"signed64", 8, nil},
	9:  ipfixDataType{"float32", 4, nil},
	10: ipfixDataType{"float64", 8, nil},
	11: ipfixDataType{"boolean", 1, nil},
	12: ipfixDataType{"macAddress", 6, nil},
	13: ipfixDataType{"string", -1, func(b []byte) string { return string(b) }},
	14: ipfixDataType{"dateTimeSeconds", 4, nil},
	15: ipfixDataType{"dateTimeMilliseconds", 4, nil},
	16: ipfixDataType{"dateTimeMicroseconds", 4, nil},
	17: ipfixDataType{"dateTimeNanoseconds", 4, nil},
	18: ipfixDataType{"ipv4Address", 4, nil},
	19: ipfixDataType{"ipv6Address", 16, nil},
	20: ipfixDataType{"basicList", -1, nil},
	21: ipfixDataType{"subTemplateList", -1, nil},
	22: ipfixDataType{"subTemplateMultiList", -1, nil},
}
