package translate

func init() {
	// Cisco IPFIX parameters, see http://docwiki.cisco.com/wiki/AVC-Export:Monitoring
	builtin[Key{9, 8232}] = InformationElementEntry{FieldID: 8232, Name: "PolicyQosClassificationHierarchy", Type: FieldTypes["unsigned24"]}
	builtin[Key{9, 9252}] = InformationElementEntry{FieldID: 9252, Name: "waas optimizationSegment", Type: FieldTypes["unsigned8"]}
	builtin[Key{9, 9265}] = InformationElementEntry{FieldID: 9265, Name: "artClient packets", Type: FieldTypes["unsigned64"]}
	builtin[Key{9, 9266}] = InformationElementEntry{FieldID: 9266, Name: "artServer packets", Type: FieldTypes["unsigned64"]}
	builtin[Key{9, 9268}] = InformationElementEntry{FieldID: 9268, Name: "artCountRetransmissions ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9272}] = InformationElementEntry{FieldID: 9272, Name: "artCountTransactions ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9273}] = InformationElementEntry{FieldID: 9273, Name: "artTotalTransactionTimeSum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9274}] = InformationElementEntry{FieldID: 9274, Name: "artTotalTransactionTimeMaximum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9275}] = InformationElementEntry{FieldID: 9275, Name: "artTotalTransactionTimeMinimum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9282}] = InformationElementEntry{FieldID: 9282, Name: "artCountNewConnections ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9292}] = InformationElementEntry{FieldID: 9292, Name: "artCountResponses ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9293}] = InformationElementEntry{FieldID: 9293, Name: "artCountResponsesHistogramBucket1 ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9294}] = InformationElementEntry{FieldID: 9294, Name: "artCountResponsesHistogramBucket2 ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9295}] = InformationElementEntry{FieldID: 9295, Name: "artCountResponsesHistogramBucket3 ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9296}] = InformationElementEntry{FieldID: 9296, Name: "artCountResponsesHistogramBucket4 ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9297}] = InformationElementEntry{FieldID: 9297, Name: "artCountResponsesHistogramBucket5 ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9298}] = InformationElementEntry{FieldID: 9298, Name: "artCountResponsesHistogramBucket6 ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9299}] = InformationElementEntry{FieldID: 9299, Name: "artCountResponsesHistogramBucket7 ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9300}] = InformationElementEntry{FieldID: 9300, Name: "artCountLateResponses ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9303}] = InformationElementEntry{FieldID: 9303, Name: "artResponseTimeSum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9304}] = InformationElementEntry{FieldID: 9304, Name: "artResponseTimeMaximum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9305}] = InformationElementEntry{FieldID: 9305, Name: "artResponseTimeMinimum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9306}] = InformationElementEntry{FieldID: 9306, Name: "artServerResponseTimeSum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9307}] = InformationElementEntry{FieldID: 9307, Name: "artServerResponseTimeMaximum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9308}] = InformationElementEntry{FieldID: 9308, Name: "artServerResponseTimeMinimum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9309}] = InformationElementEntry{FieldID: 9309, Name: "artTotalResponseTimeSum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9310}] = InformationElementEntry{FieldID: 9310, Name: "artTotalResponseTimeMaximum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9311}] = InformationElementEntry{FieldID: 9311, Name: "artTotalResponseTimeMinimum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9313}] = InformationElementEntry{FieldID: 9313, Name: "artNetworkTimeSum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9314}] = InformationElementEntry{FieldID: 9314, Name: "artNetworkTimeMaximum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9315}] = InformationElementEntry{FieldID: 9315, Name: "artNetworkTimeMinimum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9316}] = InformationElementEntry{FieldID: 9316, Name: "artClientNetworkTimeSum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9317}] = InformationElementEntry{FieldID: 9317, Name: "artClientNetworkTimeMaximum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9318}] = InformationElementEntry{FieldID: 9318, Name: "artClientNetworkTimeMinimum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9319}] = InformationElementEntry{FieldID: 9319, Name: "artServerNetworkTimeSum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9320}] = InformationElementEntry{FieldID: 9320, Name: "artServerNetworkTimeMaximum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9321}] = InformationElementEntry{FieldID: 9321, Name: "artServerNetworkTimeMinimum ", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9357}] = InformationElementEntry{FieldID: 9357, Name: "applicationHttpUriStatistics", Type: FieldTypes["octetArray"]}
	builtin[Key{9, 9360}] = InformationElementEntry{FieldID: 9360, Name: "PolicyQosQueue index", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9360}] = InformationElementEntry{FieldID: 9360, Name: "PolicyQosQueue INDEX", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 9361}] = InformationElementEntry{FieldID: 9361, Name: "PolicyQosQueue drops", Type: FieldTypes["unsigned64"]}
	builtin[Key{9, 12232}] = InformationElementEntry{FieldID: 12232, Name: "applicationCategoryName", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 12233}] = InformationElementEntry{FieldID: 12233, Name: "applicationSubCategoryName", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 12234}] = InformationElementEntry{FieldID: 12234, Name: "applicationGroupName", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 12235}] = InformationElementEntry{FieldID: 12235, Name: "applicationHttpUser-agent", Type: FieldTypes["octetArray"]}
	builtin[Key{9, 12243}] = InformationElementEntry{FieldID: 12243, Name: "applicationTraffic-class", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 12244}] = InformationElementEntry{FieldID: 12244, Name: "applicationBusiness-relevance", Type: FieldTypes["unsigned32"]}
	builtin[Key{9, 32733}] = InformationElementEntry{FieldID: 32733, Name: "timestampAbsoluteMonitoring-interval", Type: FieldTypes["unsigned64"]}
}
