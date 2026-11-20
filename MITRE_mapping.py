MITRE_MAPPING = {

    "PROCESS_DISCOVERY": {
        "id": "T1057",
        "name": "Process Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1057/",
        "confidence": "MEDIUM"
    },

    "SYSTEM_NETWORK_CONNECTIONS_DISCOVERY": {
        "id": "T1049",
        "name": "System Network Connections Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1049/",
        "confidence": "MEDIUM"
    },

    "COMMAND_AND_SCRIPTING_INTERPRETER": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/",
        "confidence": "LOW"
    },

        "NETWORK_PORT_SCAN": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "confidence": "MEDIUM"
    }
}


def get_mitre_mapping(event_type):

    mapping = MITRE_MAPPING.get(event_type.upper())

    if mapping:
        return {
            **mapping,
            "status": "CANDIDATE"
        }

    return {
        "id": None,
        "name": "No mapped ATT&CK technique",
        "tactic": None,
        "url": "https://attack.mitre.org/",
        "confidence": None,
        "status": "NOT_MAPPED"
    }


def enrich_event_with_mitre(event):

    enriched_event = event.copy()

    mapping = get_mitre_mapping(
        event.get("type", "")
    )

    enriched_event.update({
        "mitre_id": mapping["id"],
        "mitre_name": mapping["name"],
        "mitre_tactic": mapping["tactic"],
        "mitre_url": mapping["url"],
        "mitre_confidence": mapping["confidence"],
        "mitre_status": mapping["status"]
    })

    return enriched_event
