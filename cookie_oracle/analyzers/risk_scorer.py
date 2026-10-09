def calculate_risk_score(platform, flags, privilege='unknown'):
    score = 0

    # Base score based on platform sensitivity
    sensitive_platforms = {
        'Google': 90,
        'Microsoft': 90,
        'GitHub': 80,
        'Instagram': 70,
        'Facebook': 75,
        'Amazon': 75,
        'Twitter': 60
    }

    if platform in sensitive_platforms:
        score += sensitive_platforms[platform]
    else:
        score += 30  # Unknown platforms get medium base score

    # Adjust based on cookie flags
    if not flags.get('has_secure', True):
        score -= 20
    if not flags.get('has_httponly', True):
        score -= 15
    samesite = flags.get('samesite', 'Strict')
    if samesite == 'None':
        score -= 10
    elif samesite == 'Lax':
        score -= 5

    # Privilege level adjustment
    privilege_scores = {
        'guest': 10,
        'user': 20,
        'moderator': 50,
        'admin': 80,
        'root': 100,
        'super_admin': 100
    }

    score += privilege_scores.get(privilege.lower(), 20)

    # Clamp between 0 and 100
    score = max(0, min(score, 100))
    return int(score)

def get_risk_level(score):
    if score >= 80:
        return "High"
    elif score >= 50:
        return "Medium"
    else:
        return "Low"

def generate_exploitation_matrix(flags):
    matrix = []

    matrix.append({
        'method': 'Session Hijacking',
        'possible': not flags.get('has_secure', True),
        'notes': 'Cookie sent over HTTP can be intercepted via network sniffing'
    })

    matrix.append({
        'method': 'Session Fixation',
        'possible': not flags.get('has_httponly', True),
        'notes': 'Cookie accessible via JavaScript may enable fixation attacks'
    })

    samesite = flags.get('samesite', 'None')
    matrix.append({
        'method': 'CSRF',
        'possible': samesite != 'Strict',
        'notes': 'Cross-Site Request Forgery possible due to weak SameSite policy'
    })

    matrix.append({
        'method': 'Replay Attack',
        'possible': True,  # Assume always possible unless proven otherwise
        'notes': 'Ensure server-side session expiry and binding to prevent replay'
    })

    return matrix