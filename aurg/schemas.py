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


UPDATE_AI_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "packages": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
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
                "required": ["name", "verdict", "findings", "summary"],
            },
        },
    },
    "required": ["packages"],
}
