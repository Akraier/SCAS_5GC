from utilities import *
import json
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

nas_int_algs = {
    0 : "5GIA0",
    1 : "128 5GIA1",
    2 : "128 5GIA2",
    3 : "128 5GIA3",
    4 : "5GIA4",
    5 : "5GIA5",
    6 : "5GIA6",
    7 : "5GIA7"
}

nas_enc_algs = {
    0 : "5GEA0",
    1 : "128 5GEA1",
    2 : "128 5GEA2",
    3 : "128 5GEA3",
    4 : "5GEA4",
    5 : "5GEA5",
    6 : "5GEA6",
    7 : "5GEA7"
}

message_type_dict = {
    65: "Registration request",                        # 0b01000001 MOBILITY MANAGEMENT
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
    91: "Identity request",                            # 0b01011011
    92: "Identity response",                           # 0b01011100
    93: "Security mode command",                       # 0b01011101
    94: "Security mode complete",                      # 0b01011110
    95: "Security mode reject",                        # 0b01011111
    96: "5GMM status",                                 # 0b01100000
    97: "Notification",                                # 0b01100001
    98: "Notification response",                       # 0b01100010
    99: "UL NAS transport",                            # 0b01100011
    100: "DL NAS transport",                           # 0b01100100
    101: "Relay key request",                          # 0b01100101
    102: "Relay key accept",                           # 0b01100110
    103: "Relay key reject",                           # 0b01100111
    104: "Relay authentication request",               # 0b01101000
    105: "Relay authentication response",              # 0b01101001
    193: "PDU session establishment request",          # 0b11000001 SESSION MANAGEMENT 
    194: "PDU session establishment accept",           # 0b11000010
    195: "PDU session establishment reject",           # 0b11000011
    196: "PDU session authentication command",         # 0b11000100
    197: "PDU session authentication complete",        # 0b11000101
    198: "PDU session authentication result",          # 0b11000110
    199: "PDU session modification request",           # 0b11000111
    200: "PDU session modification reject",            # 0b11001000
    201: "PDU session modification command",           # 0b11001001
    202: "PDU session modification complete",          # 0b11001010
    203: "PDU session modification command reject",    # 0b11001011
    204: "PDU session release request",                # 0b11001100
    205: "PDU session release reject",                 # 0b11001101
    206: "PDU session release command",                # 0b11001110
    207: "PDU session release complete",               # 0b11001111
    208: "5GSM status",                                # 0b11010000
    209: "Service-level authentication command",       # 0b11010001
    210: "Service-level authentication complete",      # 0b11010010
    211: "Remote UE report",                           # 0b11010011
    212: "Remote UE report response"                   # 0b11010100
}
epd_enum = {
        46: "Session Management Message",
        126: "Mobility Management Message"
    }
sht_enum = {
    0:"PlainNAS",
    1:"Integrity",
    2:"Integrity + Encryption",
    3:"Integrity by 5GNAS Security Context",
    4:"Integrity + Encryption by 5GNAS Security Context"
}
reverse_epd_enum = {v: k for k, v in epd_enum.items()}
reverse_sht_enum = {v: k for k, v in sht_enum.items()}
reverse_message_type_dict = {v: k for k, v in message_type_dict.items()}

id_NAS_PDU = 38
MM_epd = 126
SM_epd = 46

"""
NAS Serialization & Deserialization class

!!! Incomplete, dissection of every NAS message not available. 
    Generic payload value is used !!!

Correctly handles Plain and Security Protected NAS messages.
Tested with AMF integrity only. In case of encryption enforced there could be
errors handling Plain messages
"""

class NAS:
    

    """def __init__(self,raw_data):
        self.dissect_nas_pdu(raw_data) """
    
    def build_plain_nas_pdu(self,pdu):
        #construct raw binary data from pdu dictionary
        #SERIALIZATION FUNCTION
        raw = b""
        try:
            #Reverse lookup for epd and sht values
            epd = reverse_epd_enum[pdu["epd"]]
            sht = reverse_sht_enum[pdu["sht"]]
            epd_byte = epd.to_bytes(1, byteorder='big')
            sht_byte = sht.to_bytes(1, byteorder='big')

            raw += epd_byte
            raw += sht_byte

            #handling optional pti
            pti = pdu["pti"]
            if pti != "None":
                pti_byte = pti.to_byte(1,byteorde='big')
                raw+=pti_byte
            
            #message type & value
            message_type = reverse_message_type_dict[pdu["message_type"]]
            msg_type_byte = message_type.to_bytes(1, byteorder='big')
            raw+=msg_type_byte

            message_value = bytes.fromhex(pdu["message_value"])
            raw += message_value
            
            return raw
        except Exception as e:
            print("[!]Error building plain NAS PDU:")
            traceback.print_exc()
            return None

    def build_nas_pdu(self,pdu):
        #THERE ARE NO CHECK ON INPUT CONSISTENCY
        #SERIALIZATION FUNCTION
        """ input type {SecurityProtectedNASPDU":{"epd":..,"sht":..},"PlainNASPDU":{}}} """
        try:
            
            if "SecurityProtectedNASPDU" not in pdu.keys():
                return self.build_plain_nas_pdu(pdu["PlainNASPDU"])
            #in case there is, SecurityProtected is always before Plain NAS
            raw = b""
            sec_pdu = pdu["SecurityProtectedNASPDU"]
            plain_pdu = pdu["PlainNASPDU"]

            epd = reverse_epd_enum[sec_pdu["epd"]]
            sht = reverse_sht_enum[sec_pdu["sht"]]
            mac = sec_pdu["mac"]
            seq_no = sec_pdu["seq_no"]
            plain_msg = self.build_plain_nas_pdu(plain_pdu)
            
            epd_byte = epd.to_bytes(1, byteorder='big')
            sht_byte = sht.to_bytes(1, byteorder='big')   #SHT in LSB, no further SHO needed since 0x00 by default
            mac_byte = bytes.fromhex(mac)
            seq_no_byte = seq_no.to_bytes(1, byteorder='big')
            raw = epd_byte + sht_byte + mac_byte + seq_no_byte + plain_msg
            #print("[DEBUG] serialized nas pdu", raw.hex())
            return raw
        except Exception as e:
            print(f"[!]An Error Occurred during NAS serialization {e}")
            traceback.print_exc()
            return None


    def dissect_plain_nas_pdu(self, raw, epd, sht):
        try:
            if len(raw) < 2:
                #only message_type, just for specific messages [Registration Complete]
                message_type = raw[0]
                message_value = bytes(0)
                pti = None
            elif epd == SM_epd:
                #Session Management message, PTI present
                #print("[DEBUG] Session Management Message")
                pti = raw[0]
                message_type = raw[1]
                message_value = raw[2:]
                
            elif epd == MM_epd:
                #Mobility Management message, PTI Optional
                #assume pti present
                #print("[DEBUG] Mobility Management Message")
                pti = raw[0]
                message_type = raw[1]
                message_value = raw[2:]
                #print(f"[DEBUG] Message Type: {message_type}")
                #pti should be present only in the following MM message types
                if (message_type != 12) and (message_type != 13) and (message_type != 14):
                    #pti not present, erase previous values
                    pti = "None"
                    message_type = raw[0]
                    message_value = raw[1:]
                #print(f"[DEBUG] Message Type: {hex(message_type)}")
                
            #pdu unencrypted
            pdu = {
                "epd":epd_enum[epd],
                "sht":sht_enum[sht],
                "pti":pti, #None if non-exhistent
                "message_type": message_type_dict[message_type],
                "message_value": message_value.hex()
            }
            
            return pdu
        except Exception as e:
            print("[!]Error dissecting plain NAS PDU:")
            traceback.print_exc()
            return None

    def dissect_nas_pdu(self,raw):
        pdu = {}
        pti = -1
        message_type = 0
        message_value = 0
        mac = 0
        seq_no = 0
        enc_msg = 0

        try:
            length = raw[0] 
            epd = raw[1] 
            """ if epd != MM_epd and epd != SM_epd:
                #id-NAS-PDU can have additional byte before epd because of NGAP
                #stripped it off for simplicity
                print("[DEBUG] Additional byte before epd")
                epd = raw[1]
                raw = raw[1:] """

            sht = raw[2] & 0x0F    #SHT is lower nibble bits 0-3
            #print(f"[DEBUG] Raw NAS PDU: {raw.hex()}")
            #print(f"[DEBUG] Length: {length}")
            #print(f"[DEBUG] epd value: {epd}")
            #print(f"[DEBUG] sht value: {sht}")
            if sht == 0:
                #plain NAS PDU
                #print("[DEBUG] Plain NAS PDU")
                pdu = self.dissect_plain_nas_pdu(raw[3:], epd, sht)
                if pdu != None:
                    self.pdu = {"PlainNASPDU":pdu}
                    return 1
                
            elif sht != 0:
                #security protected PDU headers
                mac = raw[3:7]
                seq_no = raw[7]
                enc_msg = raw[8:]
                #headers of plain nas pdu integrity/cipher protected
                epd_enc = enc_msg[0]
                sht_enc = enc_msg[1] & 0x0F
                pdu_enc = enc_msg[2:]
                #print(f"[DEBUG] MAC : {mac.hex()}")
                #print(f"[DEBUG] Seq.No: {seq_no}")
                #print(f"[DEBUG]EPD_ENC: {epd_enc}")
                #print(f"[DEBUG]SHT_ENC: {sht_enc}")
                #print(f"[DEBUG]PDU_END: {pdu_enc.hex()}")

                plain_pdu = self.dissect_plain_nas_pdu(pdu_enc, epd_enc, sht_enc)
                if plain_pdu is None:
                    print("[-] Error dissecting plain PDU")
                    return None
                pdu = {
                    "SecurityProtectedNASPDU":{
                        "epd":epd_enum[epd],
                        "sht":sht_enum[sht],
                        "mac":mac.hex(), 
                        "seq_no": seq_no
                    },
                    "PlainNASPDU": plain_pdu,
                }
                self.pdu = pdu
                return 1
        except Exception as e:
            print("[!]Error dissecting NAS PDU:")
            traceback.print_exc()
            return None
        
    @staticmethod
    def dissect_NAS_Sec_Alg(NAS_PDU):
        msg_v = NAS_PDU.get('PlainNASPDU').get('message_value')
        if msg_v is not None:
            raw_msg = bytes.fromhex(msg_v)
            security_algs = raw_msg[0]

            """4 LSBits"""
            int_alg = security_algs & 0x0F
            """4 MSBits"""
            cipher_alg = (security_algs & 0xF0) >> 4
            
            return [nas_enc_algs[cipher_alg], nas_int_algs[int_alg]]

        else:
            print('[!] Wrong NAS PDU')
            return None

"""
NGAP Serialization & Deserialization class

Deep de/serialization for id-NAS-PDU only.
Increase IEs coverage as for project needs
"""
class NGAP:
    pdu_type_values = { 
        0: "Initiating Message",
        2: "Successful Outcome",
        1: "Unsuccessful Outcome"
    }

    """ def __init__(self, raw_segment):
        self.segment = self.dissect_ngap_pdu(raw_segment)
        #print("[!] TYPE OF SEGMENT:", type(self.segment))
        if self.segment != None:
            self.print_ngap(self.segment)
        else:
            print("[!] Error dissecting NGAP") """
    def build__ngap_ie(self, ie_dict):
        #IE SERIALIZATION
        #input IEs dictionary {"id-ie1":"","id-ie2":"",..} -- ie_dict should be dict["IEs"]
        raw = b""
        reverse_ngap_ie_dict = {v: k for k, v in ngap_ie_dict.items()}

        try:
            #first 3 bytes are the number of IEs in the protocol
            protocol_ies = len(ie_dict)
            protocol_ies_bytes = protocol_ies.to_bytes(3, byteorder='big')
            raw += protocol_ies_bytes

            for ie_id, ie_value in ie_dict.items():
                if ie_id not in reverse_ngap_ie_dict:
                    print(f"[!] Unknown IE ID: {ie_id}")
                    return None
                #IE's first 2 bytes are its ID  
                IE_id_ = reverse_ngap_ie_dict[ie_id]
                IE_id_bytes = IE_id_.to_bytes(2, byteorder='big')
                raw += IE_id_bytes
                #3rd Byte its criticality
                IE_criticality = ie_value["IE_criticality"]
                IE_criticality_bytes = (IE_criticality << 6) & 0b11000000
                raw += IE_criticality_bytes.to_bytes(1, byteorder='big')
                #4th byte its length
                IE_length = ie_value["IE_length"]
                IE_length_bytes = IE_length.to_bytes(1, byteorder='big')
                raw += IE_length_bytes
                #NAS PDU handling
                if ie_id == "id-NAS-PDU":
                    #NAS PDU has additional length byte at its value's field very beginning
                    #Adding extra length now so build_nas_pdu its agnostic about it
                    nas_length = IE_length -1   #value's length its IE_length -1 Byte(this byte) encoding again the length
                    raw += nas_length.to_bytes(1, byteorder='big')

                    nas_pdu = ie_value.get("NAS PDU")
                    nas = NAS()
                    nas_pdu_raw = nas.build_nas_pdu(nas_pdu)
                    if nas_pdu_raw is None:
                        print("[-] Error building NAS PDU")
                        return None
                    raw += nas_pdu_raw
                else:
                    IE_value = ie_value["IE_value"]
                    IE_value_bytes = bytes.fromhex(IE_value)
                    raw += IE_value_bytes
            return raw
        except Exception as e:
            print("[!]Error building NGAP IEs:")
            traceback.print_exc()
            return None

    def build_ngap_pdu(self, ngap_dict):
        #input type
        #{"Initiating Request":{"procedure_code":x,"criticality":y,"value_length":z,"IEs":{..}}}
        pdu = b""
        try:
            reverse_pdu_type_values = {v: k for k, v in self.pdu_type_values.items()}
            #NGAP message type
            ngap_msg_type = list(ngap_dict.keys())[0]
            pdu_data = ngap_dict[ngap_msg_type]
            #first byte is pdu type MSB & reserved bytes LSB
            pdu_type = reverse_pdu_type_values[ngap_msg_type]
            first_byte = (pdu_type << 4) & 0b11110000   
            pdu += first_byte.to_bytes(1, byteorder='big')   #cant concat int to bytes
            #second byte is procedure code
            procedure_code = pdu_data["procedure_code"]
            second_byte = procedure_code.to_bytes(1, byteorder='big')
            pdu += second_byte
            #third byte is criticality in the first 2 bits of the MS Byte
            criticality = pdu_data["criticality"]
            third_byte = (criticality << 6) & 0b11000000
            pdu += third_byte.to_bytes(1, byteorder='big')

            #length of the following values in BER encoding
            length = pdu_data["value_length"]
            if length < 127:
                length_byte = length.to_bytes(1, byteorder='big')
            else:
                #indefinite BER encoding length
                #0x80 + 1 byte length
                msb = 0x80
                length_byte = (0x80 << 8) | length.to_bytes(1, byteorder='big')
            pdu += length_byte

            #IEs serialization
            ies_dict = pdu_data["IEs"]
            IEs = self.build__ngap_ie(ies_dict)
            if IEs is None:
                print("[-] Error building IEs")
                return None
            pdu += IEs            
            #padding
            if len(IEs) < length:
                #print("[DEBUG] Padding")
                padding = b'\x00' * (length - len(IEs))
                pdu += padding
                return  pdu 
            
            return pdu

        except Exception as e:
            print("[!]Error building NGAP PDU:")
            traceback.print_exc()
            return None
    
    def dissect_ngap_ie(self, raw_segment):
        #takes in input ngap value payload and dissects it in IEs
        #return a dictionary of IEs {id: {IE_criticality, IE_length, IE_value}, ...}

        try:
            if raw_segment is None or len(raw_segment) < 4:
                print("[!]Empty NGAP value")
                return None
            protocol_ies = int.from_bytes(raw_segment[:3], byteorder='big')   #3 bytes
            #raw_segment = raw_segment[3:]
            ie = {}
            #print(f"[DEBUG] Protocol IEs: {protocol_ies}")
            raw_segment = raw_segment[3:]   #update ngap value
            for i in range(protocol_ies):
                #print(f"[DEBUG] Remaining IEs: {raw_segment.hex()}")
                #IE_id = int.from_bytes(raw_segment[:2],byteorder='big')     #IE id, 2 bytes
                IE_id = int.from_bytes(raw_segment[:2],byteorder='big')     #IE id, 2 bytes
                IE_criticality = (raw_segment[2] & 0b11000000) >> 6  #IE criticality, 2 bits
                IE_length = raw_segment[3]   #IE length, 1 byte
                IE_value = raw_segment[4:4+IE_length]    #IE value, variable length
                #print(f"[DEBUG] IE ID: {IE_id}")
                if IE_id == id_NAS_PDU:
                    #print("[DEBUG] Dissecting NAS PDU")
                    #dissect NAS PDU
                    nas = NAS()
                    if not nas.dissect_nas_pdu(IE_value):
                        print("[-] Error dissecting NAS PDU")
                        return None
                    else:
                        ie[ngap_ie_dict[IE_id]] = {"IE_criticality": IE_criticality, "IE_length": IE_length, "NAS PDU": nas.pdu}
                #update dictionary
                elif IE_id in ngap_ie_dict and IE_id != id_NAS_PDU:
                    ie[ngap_ie_dict[IE_id]] = {"IE_criticality": IE_criticality, "IE_length": IE_length, "IE_value": IE_value.hex()}
                elif IE_id not in ngap_ie_dict:
                    #Atypical case, NGAP length is bigger than 217 bytes,
                    #print(f"[DEBUG] Atypical Segment: {raw_segment.hex()}")
                    self.dissect_ngap_ie(raw_segment[2:])
                    ie[ngap_ie_dict[IE_id]] = {"IE_criticality": IE_criticality, "IE_length": IE_length, "IE_value": IE_value.hex()}
                    break
                
                #print(f"[DEBUG] IE building : {ie}")
                raw_segment = raw_segment[4+IE_length:]   #update ngap value

            #print(f"[DEBUG] IE completed: {ie}")
            return ie

        except Exception as e:
            print("[!]Error dissecting ngap ie:")
            traceback.print_exc()
            return None

    def dissect_ngap_pdu(self, chunk_data):
        #Dissect SCTP Chunk data in NGAP PDU frame
        try:
            ngap = {}
            first_byte = chunk_data[0]
            pdu_type = (first_byte & 0b11110000) >> 4
            reserved = first_byte & 0b00001111
            procedure_code = chunk_data[1]
            criticality = (chunk_data[2] & 0b11000000) >> 6
            #ASN1 BER length Encoding. Following Length extraction could be prone to error for high length packets
            #ASN1 encoding is not clear for free5gc and probably broken  CVE-2022-43677. 
            #0x80 + 1 byte length used for length > 127
            if len(chunk_data) <= 127:
                value_length = chunk_data[3]
                value = chunk_data[4:4+value_length]

            else:
                value_length = chunk_data[4]
                value = chunk_data[5:5+value_length]
            """ print(f"[DEBUG] First Byte: {first_byte}")
            print(f"[DEBUG] Reserved: {reserved}")
            print(f"[DEBUG] PDU Type: {pdu_type}")
            print(f"[DEBUG] Procedure Code: {procedure_code}")
            print(f"[DEBUG] Criticality: {criticality}") 
            print(f"[DEBUG] Value Length: {value_length}")
            print(f"[DEBUG] Value: {value.hex()}")"""
            IEs = self.dissect_ngap_ie(value)    #returns a dictionary containing all IEs in the packet
            if IEs is None:
                print("[-] Error dissecting IEs")
                return 0
            #print(f"[+] Dissected IEs: {IEs}")
            ngap[self.pdu_type_values[pdu_type]] = {"procedure_code": procedure_code, "criticality": criticality, "value_length": value_length, "IEs": IEs, "raw": chunk_data.hex()}
            self.segment = ngap
            return 1 
        except Exception as e:
            print("[!]Error dissecting ngap:", e)
            return 0
        
    def get_nas_pdu(self):
        #utility function to extract NAS PDU from NGAP dictionary
        top_key = next(iter(self.segment))
        ies = self.segment[top_key].get("IEs", {})
        nas_pdu_entry = ies.get("id-NAS-PDU")
        if not nas_pdu_entry:
            return None
        return nas_pdu_entry.get("NAS PDU", {})
    
    def print_ngap(self):
        #Utility function for printing NGAP in any of its fields
        try:
            print("[>>] Print NGAP PDU")
            print(json.dumps(self.segment,indent=4))
            """ for pdu_type, pdu_details in ngap.items():
                print(f"\t[>>] PDU Type: {pdu_type}")
                print(f"\t[>>] Procedure Code: {pdu_details['procedure_code']}")
                print(f"\t[>>] Criticality: {pdu_details['criticality']}")
                print(f"\t[>>] Value Length: {pdu_details['value_length']}")
                IEs = pdu_details['IEs']
                for IE_id, IE in IEs.items():
                    print(f"\t[>>] IE ID: {IE_id}")
                    print(f"\t\t[>>] IE Criticality: {IE['IE_criticality']}")
                    print(f"\t\t[>>] IE Length: {IE['IE_length']}")
                    print(f"\t\t[>>] IE Value: {IE['IE_value'].hex()}") """
            return
        except Exception as e:
            print("[!]Error printing ngap:")
            traceback.print_exc()            
            return
        