# SCAS_5GC
Configurations:
- Free5gc

- Open5gs

- OpenAirInterface
    Copia uecfg.yaml, gnbcfg.yaml sotto /docker-compose/conf
    Copia docker-compose-oai-scascan5g.yaml sotto /docker-compose
    Copia la cartella mitm-proxy sotto /docker-compose
    copia la cartella ueransim sotto /docker-compose
    
    Assicurarsi che uecfg.yaml gnbcfg.yaml siano allineati con le informazioni presenti all'interno del db mysql di oai.
    basic_nrf_config.yaml di default usa NIA0, NEA0 ma UERANSIM non supporta l'emergency registration. Accertarsi di utilizzare almeno NIA1 come algoritmo prioritario. 
    Default password per mysql * linux * .

    UPDATE SessionManagementSubscriptionData SET singleNssai='{"sst": 1}', dnnConfigurations='{"default": {"sscModes": {"defaultSscMode": "SSC_MODE_1"}, "sessionAmbr": {"uplink": "100Mbps", "downlink": "100Mbps"}, "5gQosProfile": {"5qi": 6, "arp": {"preemptCap": "NOT_PREEMPT","preemptVuln": "NOT_PREEMPTABLE", "priorityLevel": 1}, "priorityLevel": 1}, "pduSessionTypes": {"defaultSessionType": "IPV4"}}}' WHERE ueid='208950000000031';

    INSERT INTO AccessAndMobilitySubscriptionData (ueid, servingPlmnid, subscribedUeAmbr, nssai) VALUES ('208950000000031', '20895', '{"uplink": "1 Gbps", "downlink": "2 Gbps"}', '{"defaultSingleNssais": [{"sst": 1}]}');

