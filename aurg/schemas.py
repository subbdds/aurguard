AI_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["Safe", "Review", "Dangerous"]},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "severity": {"type": "string", "enum": ["Safe", "Review", "Dangerous"]},
                    "reason": {"type": "string"},
                },
                "required": ["file", "line", "severity", "reason"],
            },
        },
        "summary": {"type": "string"},
    },
    "required": ["verdict", "findings", "summary"],
}


BATCH_AI_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "results": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "package": {"type": "string"},
                    "verdict": {"type": "string", "enum": ["Safe", "Review", "Dangerous"]},
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "file": {"type": "string"},
                                "line": {"type": "integer"},
                                "severity": {"type": "string", "enum": ["Safe", "Review", "Dangerous"]},
                                "reason": {"type": "string"},
                            },
                            "required": ["file", "line", "severity", "reason"],
                        },
                    },
                    "summary": {"type": "string"},
                },
                "required": ["package", "verdict", "findings", "summary"],
            },
        },
    },
    "required": ["results"],
}
