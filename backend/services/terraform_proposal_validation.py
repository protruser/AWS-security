"""Fail closed checks between diagnosis, Terraform state, AI plan and source diff."""
import difflib
import re

from services.patch_security import PatchError
from services.terraform_mapping import RULES, RULE_TARGETS, resource_prefixes


DECLARATION = re.compile(r'^[ \t]*resource\s+"(aws_[a-z0-9_]+)"\s+"([A-Za-z0-9_-]+)"\s*\{', re.M)
ASSIGNMENT = re.compile(r'^\s*([A-Za-z_][\w-]*)\s*=')
CIDR = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\w)')
REFERENCE = re.compile(r'\b(?:aws_[a-z0-9_]+|var|local|module)\.[A-Za-z0-9_-]+')
AWS_ID = re.compile(r'\b(?:sg|subnet|vpc|i|vol|rtb|acl)-[0-9a-f]{8,17}\b')


def _fail(code, detail):
    raise PatchError(code, detail)


def declarations(content):
    """Locate literal resource blocks while respecting strings and comments."""
    found = {}
    for match in DECLARATION.finditer(content):
        start, pos, depth, quote = match.start(), match.end() - 1, 0, False
        while pos < len(content):
            char = content[pos]
            if quote:
                if char == '\\':
                    pos += 2
                    continue
                if char == '"':
                    quote = False
            elif char == '"':
                quote = True
            elif char == '#':
                end = content.find('\n', pos)
                pos = len(content) if end < 0 else end
                continue
            elif content.startswith('//', pos):
                end = content.find('\n', pos)
                pos = len(content) if end < 0 else end
                continue
            elif char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    key = (match.group(1), match.group(2))
                    if key in found:
                        _fail('INVALID_TERRAFORM_STRUCTURE', f'Duplicate resource declaration: {key[0]}.{key[1]}')
                    found[key] = (start, pos + 1, content[start:pos + 1])
                    break
            pos += 1
        else:
            _fail('INVALID_TERRAFORM_STRUCTURE', f'Unclosed resource: {match.group(1)}.{match.group(2)}')
    return found


def _identity_for(resource_id, state, address):
    matches = state.get(resource_id.lower(), set())
    selected = [identity for identity, candidate in matches if candidate == address]
    if len(selected) != 1:
        _fail('PLAN_STATE_MISMATCH', f'{resource_id}: planned Terraform address is absent or ambiguous in state')
    return selected[0]


def _finding_evidence(finding, resource_id):
    return [row for row in finding.get('evidence', [])
            if isinstance(row, dict) and re.search(
                r'(?<![A-Za-z0-9_-])' + re.escape(resource_id) + r'(?![A-Za-z0-9_-])',
                str(row.get('resource', '')) + ' ' + str(row.get('value', '')), re.I)
            and isinstance(row.get('value'), str) and row['value'].strip()]


def _normalized(value):
    return re.sub(r'[^a-z0-9]', '', str(value).lower())


def _contains_value(source, value):
    if value.isdigit() or value.lower() in ('true', 'false'):
        return bool(re.search(r'(?<![A-Za-z0-9])' + re.escape(value) + r'(?![A-Za-z0-9])', source, re.I))
    return value.lower() in source.lower()


def _block_key(address):
    match = re.search(r'(aws_[a-z0-9_]+)\.([A-Za-z0-9_-]+)(?:\[.+\])?$', address)
    if not match:
        _fail('INVALID_REMEDIATION_PLAN', f'Invalid Terraform address: {address}')
    return match.group(1), match.group(2)


def validate_plan(plan, findings, files, state, mapping):
    if not isinstance(plan, dict) or not isinstance(plan.get('items'), list) or not state:
        _fail('INVALID_REMEDIATION_PLAN', 'Plan or Terraform state is missing')
    paths = {item['file_path']: declarations(item['original_content']) for item in files}
    if any(not isinstance(f.get('resource_ids'), list) or not f['resource_ids']
           or any(not isinstance(rid, str) or not rid.strip() for rid in f['resource_ids'])
           for f in findings):
        _fail('INSUFFICIENT_EVIDENCE', 'Every selected FAIL rule needs explicit AWS resource IDs')
    expected = {(str(f['rule_id']), rid) for f in findings for rid in f.get('resource_ids', [])}
    if not expected:
        _fail('INSUFFICIENT_EVIDENCE', 'Every selected FAIL rule needs explicit AWS resource IDs')
    if any(rule not in RULES or f.get('status') != 'FAIL' for f in findings for rule in [str(f['rule_id'])]):
        _fail('INVALID_REMEDIATION_PLAN', 'Plan contains an unknown or non-FAIL rule')
    actual = [(str(item.get('rule_id')), item.get('resource_id')) for item in plan['items'] if isinstance(item, dict)]
    if (len(actual) != len(plan['items']) or any(not isinstance(rid, str) for _, rid in actual)
            or len(actual) != len(set(actual)) or set(actual) != expected):
        _fail('PLAN_COVERAGE', f'Plan must account for every diagnosed resource: {sorted(expected - set(actual))}')
    by_rule = {str(f['rule_id']): f for f in findings}
    source_grounding = ''.join(file['original_content'] for file in files)
    modifications = []
    for item in plan['items']:
        rule, rid, status = str(item['rule_id']), item['resource_id'], item.get('status')
        finding = by_rule[rule]
        evidence = _finding_evidence(finding, rid)
        if not evidence:
            _fail('INSUFFICIENT_EVIDENCE', f'{rule}/{rid}: resource-specific diagnosis evidence is missing')
        cited = item.get('evidence')
        if not isinstance(cited, list) or not cited or any(row not in evidence for row in cited):
            _fail('INVALID_REMEDIATION_PLAN', f'{rule}/{rid}: plan evidence is not in the diagnosis')
        if status == 'no_change':
            expected_value = str(finding.get('expected_value', '')).strip().lower()
            if not item.get('reason') or not any(
                row['value'].strip().lower() == expected_value and expected_value or
                row['value'].strip().lower() in ('pass', 'compliant') for row in cited
            ):
                _fail('INSUFFICIENT_EVIDENCE', f'{rule}/{rid}: non-violation is not proven')
            continue
        if status != 'modify':
            _fail('PLAN_BLOCKED', f'{rule}/{rid}: {item.get("reason") or "cannot safely modify"}')
        if (not isinstance(item.get('violation'), str) or not item['violation'].strip()
                or not isinstance(item.get('expected_setting'), str) or not item['expected_setting'].strip()
                or not isinstance(item.get('preserve'), list)
                or not all(isinstance(value, str) for value in item['preserve'])
                or not isinstance(item.get('required_information'), list)):
            _fail('INVALID_REMEDIATION_PLAN', f'{rule}/{rid}: missing change rationale or operating assessment')
        expected_value = str(finding.get('expected_value', '')).strip().lower()
        if expected_value and all(row['value'].strip().lower() == expected_value for row in cited):
            _fail('PLAN_UNGROUNDED', f'{rule}/{rid}: evidence already equals expected setting')
        if item.get('required_information'):
            _fail('MISSING_OPERATIONAL_INFO', f'{rule}/{rid}: {item["required_information"]}')
        planned_targets = item.get('targets', [item])
        if not isinstance(planned_targets, list) or not planned_targets or not all(
                isinstance(target, dict) for target in planned_targets):
            _fail('INVALID_REMEDIATION_PLAN', f'{rule}/{rid}: no Terraform targets')
        for target in planned_targets:
            address = target.get('terraform_address')
            identity = _identity_for(rid, state, address)
            types = RULE_TARGETS.get(rule)
            prefixes = resource_prefixes(finding) if not types else ()
            if not (identity[0] in types if types else any(identity[0].startswith(p) for p in prefixes)):
                _fail('PLAN_STATE_MISMATCH', f'{rule}/{rid}: Terraform resource type does not match the rule')
            path = target.get('file_path')
            if path not in paths or path not in mapping.get(rule, []):
                _fail('PLAN_STATE_MISMATCH', f'{rule}/{rid}: selected Terraform file is unavailable')
            key = identity[:2]
            module = identity[2]
            if not module or not path.startswith('modules/' + module.split('.')[-1].removeprefix('module.') + '/'):
                _fail('PLAN_STATE_MISMATCH', f'{rule}/{rid}: state module differs from selected file')
            if key not in paths[path]:
                _fail('PLAN_STATE_MISMATCH', f'{rule}/{rid}: state declaration differs')
            changes = target.get('changes')
            if not isinstance(changes, list) or not changes:
                _fail('INVALID_REMEDIATION_PLAN', f'{rule}/{rid}: no concrete changes')
            original = paths[path][key][2]
            grounding = str(finding) + original
            for change in changes:
                if not isinstance(change, dict):
                    _fail('INVALID_REMEDIATION_PLAN', f'{rule}/{rid}: invalid change')
                before, after = change.get('before'), change.get('after')
                if not isinstance(before, str) or not isinstance(after, str) or not after.strip() or '\n' in before or '\n' in after:
                    _fail('INVALID_REMEDIATION_PLAN', f'{rule}/{rid}: changes must be single lines')
                if before and before not in original.splitlines():
                    _fail('PLAN_UNGROUNDED', f'{rule}/{rid}: original setting not found: {before.strip()}')
                before_key = ASSIGNMENT.match(before) if before else None
                after_key = ASSIGNMENT.match(after)
                if not after_key or (before and not before_key) or (before_key and before_key.group(1) != after_key.group(1)):
                    _fail('INVALID_REMEDIATION_PLAN', f'{rule}/{rid}: setting names differ')
                if re.search(r'\begress\s*=\s*\[\s*\]', after):
                    _fail('UNSAFE_REMEDIATION', f'{rule}/{rid}: blanket egress denial is not a supported default')
                if rule in ('3.1', '3.2') and any(cidr in after for cidr in ('0.0.0.0/0', '::/0')):
                    _fail('UNSAFE_REMEDIATION', f'{rule}/{rid}: unrestricted security group CIDR is not a remediation')
                setting = _normalized(after_key.group(1))
                if not any(setting in _normalized(str(row.get('path', '')) + ' ' + row['value'])
                           for row in cited):
                    _fail('PLAN_UNGROUNDED', f'{rule}/{rid}: edited setting lacks diagnosis evidence: {after_key.group(1)}')
                if before:
                    previous = before.split('=', 1)[1]
                    old_values = re.findall(r'"([^"\n]+)"', previous)
                    old_values += re.findall(r'\b(?:true|false|\d+)\b',
                                             re.sub(r'"[^"\n]*"', '', previous))
                    if any(not any(_contains_value(row['value'], value) for row in cited) for value in old_values):
                        _fail('PLAN_UNGROUNDED', f'{rule}/{rid}: original setting value lacks diagnosis evidence')
                if CIDR.search(after) and any(value not in grounding for value in CIDR.findall(after)):
                    _fail('MISSING_OPERATIONAL_INFO', f'{rule}/{rid}: CIDR is not grounded in diagnosis or source')
                for value in REFERENCE.findall(after) + AWS_ID.findall(after):
                    if value not in (source_grounding if value.startswith(('aws_', 'var.', 'local.', 'module.')) else grounding):
                        _fail('PLAN_UNGROUNDED', f'{rule}/{rid}: new resource reference is not grounded: {value}')
                rhs = after.split('=', 1)[1]
                literals = re.findall(r'"([^"\n]+)"', rhs)
                literals += re.findall(r'\b(?:true|false|\d+)\b', re.sub(r'"[^"\n]*"', '', rhs))
                if any(not _contains_value(grounding, value) for value in literals):
                    _fail('PLAN_UNGROUNDED', f'{rule}/{rid}: new setting value is absent from diagnosis and source')
                if rule in ('3.1', '3.2'):
                    intended = str(finding.get('expected_value', '')) + ' ' + str(finding.get('recommendation', ''))
                    if any(not _contains_value(intended, value) for value in literals):
                        _fail('MISSING_OPERATIONAL_INFO', f'{rule}/{rid}: security group target value is not specified')
                if after_key.group(1) in ('from_port', 'to_port', 'port'):
                    numbers = re.findall(r'\b\d+\b', after.split('=', 1)[1])
                    if any(not re.search(r'(?<!\d)' + re.escape(number) + r'(?!\d)', grounding)
                           for number in numbers):
                        _fail('MISSING_OPERATIONAL_INFO', f'{rule}/{rid}: port is not grounded in diagnosis or source')
        modifications.append(item)
    if not modifications:
        _fail('NO_CHANGES', 'No verified violating resource needs a Terraform change')
    return modifications


def validate_generated_files(plan, files):
    """Require each changed line inside a planned resource to match a planned edit."""
    planned = [item for item in plan['items'] if item['status'] == 'modify']
    by_block = {}
    for item in planned:
        for target in item.get('targets', [item]):
            key = (target['file_path'], *_block_key(target['terraform_address']))
            edits = by_block.setdefault(key, [])
            for change in target['changes']:
                if change not in edits:
                    edits.append(change)
    changed = set()
    for file in files:
        path, original, proposed = file['file_path'], file['original_content'], file.get('proposed_content', '')
        old, new = declarations(original), declarations(proposed)
        if list(old) != list(new):
            _fail('PROPOSAL_SCOPE', f'{path}: resource declarations changed')
        def outside(content, blocks):
            for start, end, _ in sorted(blocks.values(), reverse=True):
                content = content[:start] + '<resource>' + content[end:]
            return content
        if outside(original, old) != outside(proposed, new):
            _fail('PROPOSAL_SCOPE', f'{path}: content outside resource blocks changed')
        for key in old:
            before, after = old[key][2], new[key][2]
            edits = by_block.get((path, *key), [])
            if before == after:
                continue
            if not edits:
                _fail('PROPOSAL_SCOPE', f'{path}/{key[0]}.{key[1]}: unplanned resource change')
            removed, added = [], []
            for line in difflib.ndiff(before.splitlines(), after.splitlines()):
                if line.startswith('- '):
                    removed.append(line[2:])
                elif line.startswith('+ '):
                    added.append(line[2:])
            expected_removed = [edit['before'] for edit in edits if edit['before']]
            expected_added = [edit['after'] for edit in edits]
            if sorted(removed) != sorted(expected_removed) or sorted(added) != sorted(expected_added):
                _fail('PROPOSAL_PLAN_MISMATCH', f'{path}/{key[0]}.{key[1]}: code differs from planned settings')
            changed.add((path, *key))
    for key in by_block:
        if key not in changed:
            _fail('PROPOSAL_PLAN_MISMATCH', f'{key[0]}/{key[1]}.{key[2]}: planned change missing')
