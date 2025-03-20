import traceback

NGAP_procedure_code_values = {
    0: "id-AMFConfigurationUpdate",
    1: "id-AMFStatusIndication",
    2: "id-CellTrafficTrace",
    3: "id-DeactivateTrace",
    4: "id-DownlinkNASTransport",
    5: "id-DownlinkNonUEAssociatedNRPPaTransport",
    6: "id-DownlinkRANConfigurationTransfer",
    7: "id-DownlinkRANStatusTransfer",
    8: "id-DownlinkUEAssociatedNRPPaTransport",
    9: "id-ErrorIndication",
    10: "id-HandoverCancel",
    11: "id-HandoverNotification",
    12: "id-HandoverPreparation",
    13: "id-HandoverResourceAllocation",
    14: "id-InitialContextSetup",
    15: "id-InitialUEMessage",
    16: "id-LocationReportingControl",
    17: "id-LocationReportingFailureIndication",
    18: "id-LocationReport",
    19: "id-NASNonDeliveryIndication",
    20: "id-NGReset",
    21: "id-NGSetup",
    22: "id-OverloadStart",
    23: "id-OverloadStop",
    24: "id-Paging",
    25: "id-PathSwitchRequest",
    26: "id-PDUSessionResourceModify",
    27: "id-PDUSessionResourceModifyIndication",
    28: "id-PDUSessionResourceRelease",
    29: "id-PDUSessionResourceSetup",
    30: "id-PDUSessionResourceNotify",
    31: "id-PrivateMessage",
    32: "id-PWSCancel",
    33: "id-PWSFailureIndication",
    34: "id-PWSRestartIndication",
    35: "id-RANConfigurationUpdate",
    36: "id-RerouteNASRequest",
    37: "id-RRCInactiveTransitionReport",
    38: "id-TraceFailureIndication",
    39: "id-TraceStart",
    40: "id-UEContextModification",
    41: "id-UEContextRelease",
    42: "id-UEContextReleaseRequest",
    43: "id-UERadioCapabilityCheck",
    44: "id-UERadioCapabilityInfoIndication",
    45: "id-UETNLABindingRelease",
    46: "id-UplinkNASTransport",
    47: "id-UplinkNonUEAssociatedNRPPaTransport",
    48: "id-UplinkRANConfigurationTransfer",
    49: "id-UplinkRANStatusTransfer",
    50: "id-UplinkUEAssociatedNRPPaTransport",
    51: "id-WriteReplaceWarning",
    52: "id-SecondaryRATDataUsageReport",
    53: "id-UplinkRIMInformationTransfer",
    54: "id-DownlinkRIMInformationTransfer",
    55: "id-RetrieveUEInformation",
    56: "id-UEInformationTransfer",
    57: "id-RANCPRelocationIndication",
    58: "id-UEContextResume",
    59: "id-UEContextSuspend",
    60: "id-UERadioCapabilityIDMapping",
    61: "id-HandoverSuccess",
    62: "id-UplinkRANEarlyStatusTransfer",
    63: "id-DownlinkRANEarlyStatusTransfer",
    64: "id-AMFCPRelocationIndication",
    65: "id-ConnectionEstablishmentIndication",
    66: "id-BroadcastSessionModification",
    67: "id-BroadcastSessionRelease",
    68: "id-BroadcastSessionSetup",
    69: "id-DistributionSetup",
    70: "id-DistributionRelease",
    71: "id-MulticastSessionActivation",
    72: "id-MulticastSessionDeactivation",
    73: "id-MulticastSessionUpdate",
    74: "id-MulticastGroupPaging",
    75: "id-BroadcastSessionReleaseRequired",
    76: "id-TimingSynchronisationStatus",
    77: "id-TimingSynchronisationStatusReport",
    78: "id-MTCommunicationHandling",
    79: "id-RANPagingRequest",
    80: "id-BroadcastSessionTransport"
}

ngap_ie_dict = {
    0: "id-AllowedNSSAI",
    1: "id-AMFName",
    2: "id-AMFOverloadResponse",
    3: "id-AMFSetID",
    4: "id-AMF-TNLAssociationFailedToSetupList",
    5: "id-AMF-TNLAssociationSetupList",
    6: "id-AMF-TNLAssociationToAddList",
    7: "id-AMF-TNLAssociationToRemoveList",
    8: "id-AMF-TNLAssociationToUpdateList",
    9: "id-AMFTrafficLoadReductionIndication",
    10: "id-AMF-UE-NGAP-ID",
    11: "id-AssistanceDataForPaging",
    12: "id-BroadcastCancelledAreaList",
    13: "id-BroadcastCompletedAreaList",
    14: "id-CancelAllWarningMessages",
    15: "id-Cause",
    16: "id-CellIDListForRestart",
    17: "id-ConcurrentWarningMessageInd",
    18: "id-CoreNetworkAssistanceInformationForInactive",
    19: "id-CriticalityDiagnostics",
    20: "id-DataCodingScheme",
    21: "id-DefaultPagingDRX",
    22: "id-DirectForwardingPathAvailability",
    23: "id-EmergencyAreaIDListForRestart",
    24: "id-EmergencyFallbackIndicator",
    25: "id-EUTRA-CGI",
    26: "id-FiveG-S-TMSI",
    27: "id-GlobalRANNodeID",
    28: "id-GUAMI",
    29: "id-HandoverType",
    30: "id-IMSVoiceSupportIndicator",
    31: "id-IndexToRFSP",
    32: "id-InfoOnRecommendedCellsAndRANNodesForPaging",
    33: "id-LocationReportingRequestType",
    34: "id-MaskedIMEISV",
    35: "id-MessageIdentifier",
    36: "id-MobilityRestrictionList",
    37: "id-NASC",
    38: "id-NAS-PDU",
    39: "id-NASSecurityParametersFromNGRAN",
    40: "id-NewAMF-UE-NGAP-ID",
    41: "id-NewSecurityContextInd",
    42: "id-NGAP-Message",
    43: "id-NGRAN-CGI",
    44: "id-NGRANTraceID",
    45: "id-NR-CGI",
    46: "id-NRPPa-PDU",
    47: "id-NumberOfBroadcastsRequested",
    48: "id-OldAMF",
    49: "id-OverloadStartNSSAIList",
    50: "id-PagingDRX",
    51: "id-PagingOrigin",
    52: "id-PagingPriority",
    53: "id-PDUSessionResourceAdmittedList",
    54: "id-PDUSessionResourceFailedToModifyListModRes",
    55: "id-PDUSessionResourceFailedToSetupListCxtRes",
    56: "id-PDUSessionResourceFailedToSetupListHOAck",
    57: "id-PDUSessionResourceFailedToSetupListPSReq",
    58: "id-PDUSessionResourceFailedToSetupListSURes",
    59: "id-PDUSessionResourceHandoverList",
    60: "id-PDUSessionResourceListCxtRelCpl",
    61: "id-PDUSessionResourceListHORqd",
    62: "id-PDUSessionResourceModifyListModCfm",
    63: "id-PDUSessionResourceModifyListModInd",
    64: "id-PDUSessionResourceModifyListModReq",
    65: "id-PDUSessionResourceModifyListModRes",
    66: "id-PDUSessionResourceNotifyList",
    67: "id-PDUSessionResourceReleasedListNot",
    68: "id-PDUSessionResourceReleasedListPSAck",
    69: "id-PDUSessionResourceReleasedListPSFail",
    70: "id-PDUSessionResourceReleasedListRelRes",
    71: "id-PDUSessionResourceSetupListCxtReq",
    72: "id-PDUSessionResourceSetupListCxtRes",
    73: "id-PDUSessionResourceSetupListHOReq",
    74: "id-PDUSessionResourceSetupListSUReq",
    75: "id-PDUSessionResourceSetupListSURes",
    76: "id-PDUSessionResourceToBeSwitchedDLList",
    77: "id-PDUSessionResourceSwitchedList",
    78: "id-PDUSessionResourceToReleaseListHOCmd",
    79: "id-PDUSessionResourceToReleaseListRelCmd",
    80: "id-PLMNSupportList",
    81: "id-PWSFailedCellIDList",
    82: "id-RANNodeName",
    83: "id-RANPagingPriority",
    84: "id-RANStatusTransfer-TransparentContainer",
    85: "id-RAN-UE-NGAP-ID",
    86: "id-RelativeAMFCapacity",
    87: "id-RepetitionPeriod",
    88: "id-ResetType",
    89: "id-RoutingID",
    90: "id-RRCEstablishmentCause",
    91: "id-RRCInactiveTransitionReportRequest",
    92: "id-RRCState",
    93: "id-SecurityContext",
    94: "id-SecurityKey",
    95: "id-SerialNumber",
    96: "id-ServedGUAMIList",
    97: "id-SliceSupportList",
    98: "id-SONConfigurationTransferDL",
    99: "id-SONConfigurationTransferUL",
    100: "id-SourceAMF-UE-NGAP-ID",
    101: "id-SourceToTarget-TransparentContainer",
    102: "id-SupportedTAList",
    103: "id-TAIListForPaging",
    104: "id-TAIListForRestart",
    105: "id-TargetID",
    106: "id-TargetToSource-TransparentContainer",
    107: "id-TimeToWait",
    108: "id-TraceActivation",
    109: "id-TraceCollectionEntityIPAddress",
    110: "id-UEAggregateMaximumBitRate",
    111: "id-UE-associatedLogicalNG-connectionList",
    112: "id-UEContextRequest",
    114: "id-UE-NGAP-IDs",
    115: "id-UEPagingIdentity",
    116: "id-UEPresenceInAreaOfInterestList",
    117: "id-UERadioCapability",
    118: "id-UERadioCapabilityForPaging",
    119: "id-UESecurityCapabilities",
    120: "id-UnavailableGUAMIList",
    121: "id-UserLocationInformation",
    122: "id-WarningAreaList",
    123: "id-WarningMessageContents",
    124: "id-WarningSecurityInfo",
    125: "id-WarningType",
    126: "id-AdditionalUL-NGU-UP-TNLInformation",
    127: "id-DataForwardingNotPossible",
    128: "id-DL-NGU-UP-TNLInformation",
    129: "id-NetworkInstance",
    130: "id-PDUSessionAggregateMaximumBitRate",
     131: "id-PDUSessionResourceFailedToModifyListModCfm",
    132: "id-PDUSessionResourceFailedToSetupListCxtFail",
    133: "id-PDUSessionResourceListCxtRelReq",
    134: "id-PDUSessionType",
    135: "id-QosFlowAddOrModifyRequestList",
    136: "id-QosFlowSetupRequestList",
    137: "id-QosFlowToReleaseList",
    138: "id-SecurityIndication",
    139: "id-UL-NGU-UP-TNLInformation",
    140: "id-UL-NGU-UP-TNLModifyList",
    141: "id-WarningAreaCoordinates",
    142: "id-PDUSessionResourceSecondaryRATUsageList",
    143: "id-HandoverFlag",
    144: "id-SecondaryRATUsageInformation",
    145: "id-PDUSessionResourceReleaseResponseTransfer",
    146: "id-RedirectionVoiceFallback",
    147: "id-UERetentionInformation",
    148: "id-S-NSSAI",
    149: "id-PSCellInformation",
    150: "id-LastEUTRAN-PLMNIdentity",
    151: "id-MaximumIntegrityProtectedDataRate-DL",
    152: "id-AdditionalDLForwardingUPTNLInformation",
    153: "id-AdditionalDLUPTNLInformationForHOList",
    154: "id-AdditionalNGU-UP-TNLInformation",
    155: "id-AdditionalDLQosFlowPerTNLInformation",
    156: "id-SecurityResult",
    157: "id-ENDC-SONConfigurationTransferDL",
    158: "id-ENDC-SONConfigurationTransferUL",
    159: "id-OldAssociatedQosFlowList-ULendmarkerexpected",
    160: "id-CNTypeRestrictionsForEquivalent",
    161: "id-CNTypeRestrictionsForServing",
    162: "id-NewGUAMI",
    163: "id-ULForwarding",
    164: "id-ULForwardingUP-TNLInformation",
    165: "id-CNAssistedRANTuning",
    166: "id-CommonNetworkInstance",
    167: "id-NGRAN-TNLAssociationToRemoveList",
    168: "id-TNLAssociationTransportLayerAddressNGRAN",
    169: "id-EndpointIPAddressAndPort",
    170: "id-LocationReportingAdditionalInfo",
    171: "id-SourceToTarget-AMFInformationReroute",
    172: "id-AdditionalULForwardingUPTNLInformation",
    173: "id-SCTP-TLAs",
    174: "id-SelectedPLMNIdentity",
    175: "id-RIMInformationTransfer",
    176: "id-GUAMIType",
    177: "id-SRVCCOperationPossible",
    178: "id-TargetRNC-ID",
    179: "id-RAT-Information",
    180: "id-ExtendedRATRestrictionInformation",
    181: "id-QosMonitoringRequest",
    182: "id-SgNB-UE-X2AP-ID",
    183: "id-AdditionalRedundantDL-NGU-UP-TNLInformation",
    184: "id-AdditionalRedundantDLQosFlowPerTNLInformation",
    185: "id-AdditionalRedundantNGU-UP-TNLInformation",
    186: "id-AdditionalRedundantUL-NGU-UP-TNLInformation",
    187: "id-CNPacketDelayBudgetDL",
    188: "id-CNPacketDelayBudgetUL",
    189: "id-ExtendedPacketDelayBudget",
    190: "id-RedundantCommonNetworkInstance",
    191: "id-RedundantDL-NGU-TNLInformationReused",
    192: "id-RedundantDL-NGU-UP-TNLInformation",
    193: "id-RedundantDLQosFlowPerTNLInformation",
    194: "id-RedundantQosFlowIndicator",
    195: "id-RedundantUL-NGU-UP-TNLInformation",
    196: "id-TSCTrafficCharacteristics",
    197: "id-RedundantPDUSessionInformation",
    198: "id-UsedRSNInformation",
    199: "id-IAB-Authorized",
    200: "id-IAB-Supported",
    201: "id-IABNodeIndication",
    202: "id-NB-IoT-PagingDRX",
    203: "id-NB-IoT-Paging-eDRXInfo",
    204: "id-NB-IoT-DefaultPagingDRX",
    205: "id-Enhanced-CoverageRestriction",
    206: "id-Extended-ConnectedTime",
    207: "id-PagingAssisDataforCEcapabUE",
    208: "id-WUS-Assistance-Information",
    209: "id-UE-DifferentiationInfo",
    210: "id-NB-IoT-UEPriority",
    211: "id-UL-CP-SecurityInformation",
    212: "id-DL-CP-SecurityInformation",
    213: "id-TAI",
    214: "id-UERadioCapabilityForPagingOfNB-IoT",
    215: "id-LTEV2XServicesAuthorized",
    216: "id-NRV2XServicesAuthorized",
    217: "id-LTEUESidelinkAggregateMaximumBitrate",
    218: "id-NRUESidelinkAggregateMaximumBitrate",
    219: "id-PC5QoSParameters",
    220: "id-AlternativeQoSParaSetList",
    221: "id-CurrentQoSParaSetIndex",
    222: "id-CEmodeBrestricted",
    223: "id-EUTRA-PagingeDRXInformation",
    224: "id-CEmodeBSupport-Indicator",
    225: "id-LTEM-Indication",
    226: "id-EndIndication",
    227: "id-EDT-Session",
    228: "id-UECapabilityInfoRequest",
    229: "id-PDUSessionResourceFailedToResumeListRESReq",
    230: "id-PDUSessionResourceFailedToResumeListRESRes",
    231: "id-PDUSessionResourceSuspendListSUSReq",
    232: "id-PDUSessionResourceResumeListRESReq",
    233: "id-PDUSessionResourceResumeListRESRes",
    234: "id-UE-UP-CIoT-Support",
    235: "id-Suspend-Request-Indication",
    236: "id-Suspend-Response-Indication",
    237: "id-RRC-Resume-Cause",
    238: "id-RGLevelWirelineAccessCharacteristics",
    239: "id-W-AGFIdentityInformation",
    240: "id-GlobalTNGF-ID",
    241: "id-GlobalTWIF-ID",
    242: "id-GlobalW-AGF-ID",
    243: "id-UserLocationInformationW-AGF",
    244: "id-UserLocationInformationTNGF",
    245: "id-AuthenticatedIndication",
    246: "id-TNGFIdentityInformation",
    247: "id-TWIFIdentityInformation",
    248: "id-UserLocationInformationTWIF",
    249: "id-DataForwardingResponseERABList",
    250: "id-IntersystemSONConfigurationTransferDL",
    251: "id-IntersystemSONConfigurationTransferUL",
    252: "id-SONInformationReport",
    253: "id-UEHistoryInformationFromTheUE",
    254: "id-ManagementBasedMDTPLMNList",
    255: "id-MDTConfiguration",
    256: "id-PrivacyIndicator",
    257: "id-TraceCollectionEntityURI",
    258: "id-NPN-Support",
    259: "id-NPN-AccessInformation",
    260: "id-NPN-PagingAssistanceInformation",
    261: "id-NPN-MobilityInformation",
    262: "id-TargettoSource-Failure-TransparentContainer",
    263: "id-NID",
    264: "id-UERadioCapabilityID",
    265: "id-UERadioCapability-EUTRA-Format",
    266: "id-DAPSRequestInfo",
    267: "id-DAPSResponseInfoList",
    268: "id-EarlyStatusTransfer-TransparentContainer",
    269: "id-NotifySourceNGRANNode",
    270: "id-ExtendedSliceSupportList",
    271: "id-ExtendedTAISliceSupportList",
    272: "id-ConfiguredTACIndication",
    273: "id-Extended-RANNodeName",
    274: "id-Extended-AMFName",
    275: "id-GlobalCable-ID",
    276: "id-QosMonitoringReportingFrequency",
    277: "id-QosFlowParametersList",
    278: "id-QosFlowFeedbackList",
    279: "id-BurstArrivalTimeDownlink",
    280: "id-ExtendedUEIdentityIndexValue",
    281: "id-PduSessionExpectedUEActivityBehaviour",
    282: "id-MicoAllPLMN",
    283: "id-QosFlowFailedToSetupList",
    284: "id-SourceTNLAddrInfo",
    285: "id-ExtendedReportIntervalMDT",
    286: "id-SourceNodeID",
    287: "id-NRNTNTAIInformation",
    288: "id-UEContextReferenceAtSource",
    289: "id-LastVisitedPSCellList",
    290: "id-IntersystemSONInformationRequest",
    291: "id-IntersystemSONInformationReply",
    292: "id-EnergySavingIndication",
    293: "id-IntersystemResourceStatusUpdate",
    294: "id-SuccessfulHandoverReportList",
    295: "id-MBS-AreaSessionID",
    296: "id-MBS-QoSFlowsToBeSetupList",
    297: "id-MBS-QoSFlowsToBeSetupModList",
    298: "id-MBS-ServiceArea",
    299: "id-MBS-SessionID",
     300: "id-MBS-DistributionReleaseRequestTransfer",
    301: "id-MBS-DistributionSetupRequestTransfer",
    302: "id-MBS-DistributionSetupResponseTransfer",
    303: "id-MBS-DistributionSetupUnsuccessfulTransfer",
    304: "id-MulticastSessionActivationRequestTransfer",
    305: "id-MulticastSessionDeactivationRequestTransfer",
    306: "id-MulticastSessionUpdateRequestTransfer",
    307: "id-MulticastGroupPagingAreaList",
    309: "id-MBS-SupportIndicator",
    310: "id-MBSSessionFailedtoSetupList",
    311: "id-MBSSessionFailedtoSetuporModifyList",
    312: "id-MBSSessionSetupResponseList",
    313: "id-MBSSessionSetuporModifyResponseList",
    314: "id-MBSSessionSetupFailureTransfer",
    315: "id-MBSSessionSetupRequestTransfer",
    316: "id-MBSSessionSetupResponseTransfer",
    317: "id-MBSSessionToReleaseList",
    318: "id-MBSSessionSetupRequestList",
    319: "id-MBSSessionSetuporModifyRequestList",
    323: "id-MBS-ActiveSessionInformation-SourcetoTargetList",
    324: "id-MBS-ActiveSessionInformation-TargettoSourceList",
    325: "id-OnboardingSupport",
    326: "id-TimeSyncAssistanceInfo",
    327: "id-SurvivalTime",
    328: "id-QMCConfigInfo",
    329: "id-QMCDeactivation",
    331: "id-PDUSessionPairID",
    332: "id-NR-PagingeDRXInformation",
    333: "id-RedCapIndication",
    334: "id-TargetNSSAIInformation",
    335: "id-UESliceMaximumBitRateList",
    336: "id-M4ReportAmount",
    337: "id-M5ReportAmount",
    338: "id-M6ReportAmount",
    339: "id-M7ReportAmount",
    340: "id-IncludeBeamMeasurementsIndication",
    341: "id-ExcessPacketDelayThresholdConfiguration",
    342: "id-PagingCause",
    343: "id-PagingCauseIndicationForVoiceService",
    344: "id-PEIPSassistanceInformation",
    345: "id-FiveG-ProSeAuthorized",
    346: "id-FiveG-ProSeUEPC5AggregateMaximumBitRate",
    347: "id-FiveG-ProSePC5QoSParameters",
    348: "id-MBSSessionModificationFailureTransfer",
    349: "id-MBSSessionModificationRequestTransfer",
    350: "id-MBSSessionModificationResponseTransfer",
    351: "id-MBS-QoSFlowToReleaseList",
    352: "id-MBS-SessionTNLInfo5GC",
    353: "id-TAINSAGSupportList",
    354: "id-SourceNodeTNLAddrInfo",
    355: "id-NGAPIESupportInformationRequestList",
    356: "id-NGAPIESupportInformationResponseList",
    357: "id-MBS-SessionFSAIDList",
    358: "id-MBSSessionReleaseResponseTransfer",
    359: "id-ManagementBasedMDTPLMNModificationList",
    360: "id-EarlyMeasurement",
    361: "id-BeamMeasurementsReportConfiguration",
    362: "id-HFCNode-ID-new",
    363: "id-GlobalCable-ID-new",
    364: "id-TargetHomeENB-ID",
    365: "id-HashedUEIdentityIndexValue",
    366: "id-ExtendedMobilityInformation",
    367: "id-NetworkControlledRepeaterAuthorized",
    368: "id-AdditionalCancelledlocationReportingReferenceIDList",
    369: "id-Selected-Target-SNPN-Identity",
    370: "id-EquivalentSNPNsList",
    371: "id-SelectedNID",
    372: "id-SupportedUETypeList",
    373: "id-AerialUEsubscriptionInformation",
    374: "id-NR-A2X-ServicesAuthorized",
    375: "id-LTE-A2X-ServicesAuthorized",
    376: "id-NR-A2X-UE-PC5-AggregateMaximumBitRate",
    377: "id-LTE-A2X-UE-PC5-AggregateMaximumBitRate",
    378: "id-A2X-PC5-QoS-Parameters",
    379: "id-FiveGProSeLayer2Multipath",
    380: "id-FiveGProSeLayer2UEtoUERelay",
    381: "id-FiveGProSeLayer2UEtoUERemote",
    382: "id-CandidateRelayUEInformationList",
    383: "id-SuccessfulPSCellChangeReportList",
    384: "id-IntersystemMobilityFailureforVoiceFallback",
    385: "id-TargetCellCRNTI",
    386: "id-TimeSinceFailure",
    387: "id-RANTimingSynchronisationStatusInfo",
    388: "id-RAN-TSSRequestType",
    389: "id-RAN-TSSScope",
    390: "id-ClockQualityReportingControlInfo",
    391: "id-RANfeedbacktype",
    392: "id-QoSFlowTSCList",
    393: "id-TSCTrafficCharacteristicsFeedback",
    394: "id-DownlinkTLContainer",
    395: "id-UplinkTLContainer",
    396: "id-ANPacketDelayBudgetUL",
    397: "id-QosFlowAdditionalInfoList",
    398: "id-AssistanceInformationQoE-Meas",
    399: "id-MBSCommServiceType",
    400: "id-MobileIAB-Authorized",
    401: "id-MobileIAB-MTUserLocationInformation",
    402: "id-MobileIABNodeIndication",
    403: "id-NoPDUSessionIndication",
    404: "id-MobileIAB-Supported",
    405: "id-CN-MT-CommunicationHandling",
    406: "id-FiveGCAction",
    407: "id-PagingPolicyDifferentiation",
    408: "id-DL-Signalling",
    409: "id-PNI-NPN-AreaScopeofMDT",
    410: "id-PNI-NPNBasedMDT",
    411: "id-SNPN-CellBasedMDT",
    412: "id-SNPN-TAIBasedMDT",
    413: "id-SNPN-BasedMDT",
    414: "id-Partially-Allowed-NSSAI",
    415: "id-AssociatedSessionID",
    416: "id-MBS-AssistanceInformation",
    417: "id-BroadcastTransportFailureTransfer",
    418: "id-BroadcastTransportRequestTransfer",
    419: "id-BroadcastTransportResponseTransfer",
    420: "id-TimeBasedHandoverInformation",
    421: "id-DLDiscarding",
    422: "id-PDUsetQoSParameters",
    423: "id-PDUSetbasedHandlingIndicator",
    424: "id-N6JitterInformation",
    425: "id-ECNMarkingorCongestionInformationReportingRequest",
    426: "id-ECNMarkingorCongestionInformationReportingStatus",
    427: "id-ERedCapIndication",
    428: "id-XrDeviceWith2Rx",
    429: "id-UserPlaneErrorIndicator",
    430: "id-SLPositioningRangingServiceInfo",
    431: "id-PDUSessionListMTCommHReq",
    432: "id-MaximumDataBurstVolume",
    433: "id-MN-only-MDT-collection",
    434: "id-MBS-NGUFailureIndication",
    435: "id-UserPlaneFailureIndication",
    436: "id-UserPlaneFailureIndicationReport",
    437: "id-SourceSN-to-TargetSN-QMCInfo",
    438: "id-QoERVQoEReportingPaths",
    439: "id-UserLocationInformationN3IWF-without-PortNumber",
    440: "id-AUN3DeviceAccessInfo"
}

message_type_dict = {
    65: "Registration request",                        # 0b01000001
    66: "Registration accept",                         # 0b01000010
    67: "Registration complete",                       # 0b01000011
    68: "Registration reject",                         # 0b01000100
    69: "Deregistration request (UE originating)",     # 0b01000101
    70: "Deregistration accept (UE originating)",      # 0b01000110
    71: "Deregistration request (UE terminated)",      # 0b01000111
    72: "Deregistration accept (UE terminated)",       # 0b01001000
    73: "Service request",                             # 0b01001001
    74: "Service reject",                              # 0b01001010
    75: "Service accept",                              # 0b01001011
    76: "Control plane service request",               # 0b01001100
    80: "Network slice-specific authentication command", # 0b01010000
    81: "Network slice-specific authentication complete", # 0b01010001
    82: "Network slice-specific authentication result",   # 0b01010010
    84: "Configuration update command",                # 0b01010100
    85: "Configuration update complete",               # 0b01010101
    86: "Authentication request",                      # 0b01010110
    87: "Authentication response",                     # 0b01010111
    88: "Authentication reject",                       # 0b01011000
    89: "Authentication failure",                      # 0b01011001
    90: "Authentication result",                       # 0b01011010
    92: "Identity request",                            # 0b01011100
    93: "Identity response",                           # 0b01011101
    94: "Security mode command",                       # 0b01011110
    95: "Security mode complete",                      # 0b01011111
    96: "Security mode reject",                        # 0b01100000
    97: "5GMM status",                                 # 0b01100001
    98: "Notification",                                # 0b01100010
    99: "Notification response",                       # 0b01100011
    100: "UL NAS transport",                           # 0b01100100
    101: "DL NAS transport",                           # 0b01100101
    102: "Relay key request",                          # 0b01100110
    103: "Relay key accept",                           # 0b01100111
    104: "Relay key reject",                           # 0b01101000
    105: "Relay authentication request",               # 0b01101001
    106: "Relay authentication response",              # 0b01101010
    193: "PDU session establishment request",          # 0b11000001
    194: "PDU session establishment accept",           # 0b11000010
    195: "PDU session establishment reject",           # 0b11000011
    196: "PDU session authentication command",         # 0b11000100
    197: "PDU session authentication complete",        # 0b11000101
    198: "PDU session authentication result",          # 0b11000110
    200: "PDU session modification request",           # 0b11001000
    201: "PDU session modification reject",            # 0b11001001
    202: "PDU session modification command",           # 0b11001010
    203: "PDU session modification complete",          # 0b11001011
    204: "PDU session modification command reject",    # 0b11001100
    205: "PDU session release request",                # 0b11001101
    206: "PDU session release reject",                 # 0b11001110
    207: "PDU session release command",                # 0b11001111
    208: "PDU session release complete",               # 0b11010000
    209: "5GSM status",                                # 0b11010001
    210: "Service-level authentication command",       # 0b11010010
    211: "Service-level authentication complete",      # 0b11010011
    212: "Remote UE report",                           # 0b11010100
    213: "Remote UE report response"                   # 0b11010101
}

def build_plain_nas_pdu(self,pdu):
    #construct raw binary data from pdu dictionary
    #SERIALIZATION FUNCTION
    try:
        #Reverse lookup for epd and sht values
        epd = self.reverse_epd_enum[pdu["epd"]]
        sht = self.reverse_sht_enum[pdu["sht"]]

        #EPD
        epd_byte = bytes([epd])
        #SHT
        sht_byte = (0x00 << 4) | (sht & 0x0F)   #0x00 Spare Half Octet 
        sht_byte = bytes([sht_byte])
        #message type & value
        message_type = self.reverse_message_type_dict[pdu["message_type"]]
        message_value = bytes.fromhex(pdu["message_value"])

        payload = b""

        if epd == self.reverse_epd_enum["Session Management Message"]:
            #Session Management message, PTI present
            pti = pdu["pti"] if pdu["pti"] != "None" else 0x00
            payload += bytes([pti])
            payload += bytes([message_type])
        elif epd == self.reverse_epd_enum["Mobility Management Message"]:
            #PTI optional
            if message_type in [12,13,14]:
                #PTI not present
                payload += bytes([message_type])
            else:
                #PTI present
                pti = pdu["pti"] if pdu["pti"] != "None" else 0x00
                payload += bytes([pti])
                payload += bytes([message_type])
        else:
            print("[!]Unknown EPD")
            return None
        
        payload += message_value
        nas_pdu = epd_byte + sht_byte + payload
        return nas_pdu
    except Exception as e:
        print("[!]Error building plain NAS PDU:")
        traceback.print_exc()
        return None

def build_nas_pdu(self,pdu):
    #SERIALIZATION FUNCTION
    """ input type {SecurityProtectedNASPDU":{"epd":..,"sht":..},"PlainNASPDU":{}}} """

    if "SecurityProtectedNASPDU" not in pdu.keys():
        return self.build_plain_nas_pdu(pdu["PlainNASPDU"])
    
    sec_pdu = pdu["SecurityProtectedNASPDU"]
    plain_pdu = pdu["PlainNASPDU"]

    epd = self.reverse_epd_enum[sec_pdu["epd"]]
    sht = self.reverse_sht_enum[sec_pdu["sht"]]
    mac = bytes.fromhex(sec_pdu["mac"])
    seq_no = int(sec_pdu["seq_no"])
    enc_msg = self.build_plain_nas_pdu(plain_pdu)
    
    epd_byte = bytes([epd])
    sht_byte = (0xF0 | bytes(sht))   #review
    seq_no_byte = bytes(seq_no)
    raw = epd_byte + sht_byte + mac + seq_no_byte + enc_msg
    print("[DEBUG] serialized nas pdu", raw.hex())
    return raw

def build__ngap_ie(self, ie_dict):
        #IE SERIALIZATION
        #input IEs dictionary {"id-ie1":"","id-ie2":"",..} -- ie_dict should be dict["IEs"]
        try:
            reverse_ngap_ie_dict = {v: k for k, v in ngap_ie_dict.items()}
            protocol_ies = len(ie_dict)
            protocol_ies_bytes = protocol_ies.to_bytes(3, byteorder='big')
            raw = b""
            for ie_id, ie_value in ie_dict.items():
                if ie_id not in reverse_ngap_ie_dict:
                    print(f"[!] Unknown IE ID: {ie_id}")
                    return None
                IE_id_ = reverse_ngap_ie_dict[ie_id]
                IE_id_bytes = IE_id_.to_bytes(2, byteorder='big')
                IE_criticality = ie_value.get("IE_criticality")
                IE_criticality_bytes = (IE_criticality << 6).to_bytes(1, byteorder='big')
                IE_length = ie_value.get("IE_length")
                IE_length_bytes = IE_length.to_bytes(1, byteorder='big')
                #NAS PDU handling
                if ie_id == "id-NAS-PDU":
                    nas_pdu = ie_value.get("NAS PDU")
                    
                    #return raw
        except Exception as e:
            print("[!]Error building NGAP IEs:")
            traceback.print_exc()
            return None

def build_ngap_pdu(self, ngap_dict):
    try:
        reverse_pdu_type_values = {v: k for k, v in self.pdu_type_values.items()}
        pdu = b""
        #NGAP message type
        ngap_msg_type = next(iter(ngap_dict))
        pdu_data = ngap_dict[ngap_msg_type]

        pdu_type = reverse_pdu_type_values[ngap_msg_type]
        first_byte = (pdu_type << 4) & 0b11110000

        pdu += pdu_type
        reserved = 0x00
        procedure_code = pdu_data["procedure_code"].to_bytes(1, byteorder='big')
        pdu += procedure_code
        criticality = pdu_data["criticality"]
        ies_dict = pdu_data["IEs"]
        

        value = b""

    except Exception as e:
        print("[!]Error building NGAP PDU:")
        traceback.print_exc()
        return None