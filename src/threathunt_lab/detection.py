"""Detection D001 in Python, so it can run on the JSON events.

It does the same as detections/sigma/powershell_encoded_or_download_cradle.yml.
tests/test_detection.py checks that the patterns below match the Sigma file.

detect() only gets the event, never the labels.
"""

from threathunt_lab.schema import get_field

# Sigma field -> ECS field (same as sigma-cli's ecs_windows pipeline):
#   Image -> process.executable
#   OriginalFileName -> process.pe.original_file_name
#   CommandLine -> process.command_line
IMAGE_ENDSWITH = ["\\powershell.exe", "\\pwsh.exe"]
ORIGINAL_FILE_NAMES = ["PowerShell.EXE", "pwsh.dll"]
ENCODED_FLAGS = [" -e ", " -ec ", " -en ", " -enc ", " -enco"]
DOWNLOAD = ["DownloadString", "DownloadData", "Invoke-WebRequest", "Invoke-RestMethod"]
INVOKE = ["IEX", "Invoke-Expression"]

# Sigma's windash modifier: the "-" can also be "/" or a Unicode dash.
DASHES = ["-", "/", "–", "—", "―"]


def lower_field(event: dict, field: str) -> str:
    """The field in lower case, or "" if it's missing or not text."""
    value = get_field(event, field)
    return value.lower() if isinstance(value, str) else ""


def contains_any(text: str, patterns: list[str]) -> bool:
    return any(pattern.lower() in text for pattern in patterns)


def windash(patterns: list[str]) -> list[str]:
    return [pattern.replace("-", dash, 1) for pattern in patterns for dash in DASHES]


def detect(event: dict) -> bool:
    """Return True if the event should raise a D001 alert."""
    # Sigma matching ignores case, so everything is compared in lower case.
    executable = lower_field(event, "process.executable")
    original_name = lower_field(event, "process.pe.original_file_name")
    command_line = lower_field(event, "process.command_line")

    is_powershell = any(executable.endswith(end.lower()) for end in IMAGE_ENDSWITH) or (
        original_name in [name.lower() for name in ORIGINAL_FILE_NAMES]
    )
    encoded = contains_any(command_line, windash(ENCODED_FLAGS))
    download_and_run = contains_any(command_line, DOWNLOAD) and contains_any(command_line, INVOKE)

    return is_powershell and (encoded or download_and_run)
