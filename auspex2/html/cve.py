from harborapi.models.scanner import Severity

# TODO: enable custom styling so we don't have to rely on
#       the default bootstrap classes


def severity_to_colorclass(severity: Severity) -> str:
    if severity == Severity.critical:
        return "danger"
    elif severity == Severity.high:
        return "danger"
    elif severity == Severity.medium:
        return "warning"
    elif severity == Severity.low:
        return "success"
    elif severity == Severity.negligible:
        return "success"
    else:
        return "secondary"  # unknown


def cvssv3_to_colorclass(cvssv3: float) -> str:
    if cvssv3 >= 9.0:
        return "danger"
    elif cvssv3 >= 7.0:
        return "danger"
    elif cvssv3 >= 4.0:
        return "warning"
    elif cvssv3 >= 0.0:
        return "success"
    else:
        return "secondary"  # unknown
