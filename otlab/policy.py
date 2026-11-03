"""Passive policy decisions; no blocking and no LLM-generated verdicts."""
import ipaddress


def validate(policy):
    if not policy['allowed_sources']:
        raise ValueError('At least one authorized source is required')
    for source in policy['allowed_sources']:
        ipaddress.ip_address(source)
    if not 0 <= policy['unit'] <= 255:
        raise ValueError('Invalid unit ID')
    for address, bounds in policy['registers'].items():
        if not 0 <= int(address) <= 65535 or len(bounds) != 2 or not 0 <= bounds[0] <= bounds[1] <= 65535:
            raise ValueError('Invalid register bounds')
    return policy


def evaluate(request, source, policy):
    if request.unit != policy['unit']:
        return {'verdict': 'unassessed', 'reasons': ['unit_not_configured'], 'violations': []}
    if request.function == 3:
        return {'verdict': 'not_a_write', 'reasons': [], 'violations': []}
    reasons, violations = [], []
    if source not in policy['allowed_sources']:
        reasons.append('unapproved_source')
    for offset, value in enumerate(request.values):
        address = request.address + offset
        bounds = policy['registers'].get(str(address))
        if bounds is None:
            violations.append({'address': address, 'value': value, 'reason': 'register_not_allowed'})
        elif not bounds[0] <= value <= bounds[1]:
            violations.append({'address': address, 'value': value, 'allowed': bounds, 'reason': 'out_of_range'})
    reasons.extend(sorted({v['reason'] for v in violations}))
    return {'verdict': 'policy_violation' if reasons else 'allowed_write',
            'reasons': reasons, 'violations': violations}
