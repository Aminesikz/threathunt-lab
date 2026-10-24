"""Detection D002 in Python: a PHP web server starts a shell or tool (Linux).

It does the same as detections/sigma/php_web_server_starts_shell.yml.
tests/test_detection_php.py checks that the patterns below match the Sigma file.
"""

from threathunt_lab.detection import contains_any, lower_field

# Sigma field -> ECS field (detections/pipelines/ecs_linux.yml):
#   ParentImage -> process.parent.executable
#   Image -> process.executable
#   CommandLine -> process.command_line
PARENT_ENDSWITH = ["/apache2", "/httpd", "/frankenphp", "/lsphp"]
PARENT_CONTAINS = ["/php-fpm", "/php-cgi"]
CHILD_ENDSWITH = ["/sh", "/bash", "/dash", "/id", "/uname", "/whoami", "/hostname", "/wget", "/curl"]
MAIL_COMMAND = "sh -c /usr/sbin/sendmail -t -i"


def detect(event: dict) -> bool:
    """Return True if the event should raise a D002 alert."""
    # Sigma ignores case, so compare in lower case like D001.
    parent = lower_field(event, "process.parent.executable")
    child = lower_field(event, "process.executable")
    command_line = lower_field(event, "process.command_line")

    is_web_server = parent.endswith(tuple(p.lower() for p in PARENT_ENDSWITH)) or contains_any(parent, PARENT_CONTAINS)
    is_shell_or_tool = child.endswith(tuple(c.lower() for c in CHILD_ENDSWITH))
    is_mail = command_line == MAIL_COMMAND.lower()

    return is_web_server and is_shell_or_tool and not is_mail
