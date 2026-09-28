import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.patch_security import PatchError
from services.terraform_proposal_validation import validate_plan, validate_generated_files
from services.terraform_remediation_service import generate_remediation_plan, RemediationError


PATH = 'modules/network/security_groups.tf'


def fixture(count=1):
    original = ''.join(f'resource "aws_security_group" "group{i}" {{\n'
                       f'  description = "open"\n}}\n' for i in range(count))
    evidence = [{'resource': f'sg-{i}', 'path': 'ip_permissions.description.from_port', 'value': 'open'}
                for i in range(count)]
    finding = {'rule_id': '3.1', 'status': 'FAIL',
               'resource_ids': [f'sg-{i}' for i in range(count)],
               'evidence': evidence, 'expected_value': 'closed'}
    state = {f'sg-{i}': {(('aws_security_group', f'group{i}', 'module.network'),
                         f'module.network.aws_security_group.group{i}')}
             for i in range(count)}
    items = [{'rule_id': '3.1', 'resource_id': f'sg-{i}', 'status': 'modify',
              'evidence': [evidence[i]],
              'terraform_address': f'module.network.aws_security_group.group{i}',
              'file_path': PATH, 'violation': 'open ingress',
              'expected_setting': 'restricted ingress', 'preserve': ['resource identity'],
              'required_information': [], 'reason': '',
              'changes': [{'before': '  description = "open"',
                           'after': '  description = "closed"'}]} for i in range(count)]
    return {'items': items}, [finding], [{'file_path': PATH, 'original_content': original}], state, {'3.1': [PATH]}


class ProposalValidationTest(unittest.TestCase):
    def assert_code(self, plan, findings, files, state, mapping, proposed):
        validate_plan(plan, findings, files, state, mapping)
        files[0]['proposed_content'] = proposed
        validate_generated_files(plan, files)

    def test_ten_violations_one_edit_is_rejected(self):
        plan, findings, files, state, mapping = fixture(10)
        proposed = files[0]['original_content'].replace('"open"', '"closed"', 1)
        with self.assertRaises(PatchError) as error:
            self.assert_code(plan, findings, files, state, mapping, proposed)
        self.assertEqual(error.exception.code, 'PROPOSAL_PLAN_MISMATCH')

    def test_missing_state_resource_stops_plan(self):
        plan, findings, files, state, mapping = fixture(2)
        state.pop('sg-1')
        with self.assertRaises(PatchError) as error:
            validate_plan(plan, findings, files, state, mapping)
        self.assertEqual(error.exception.code, 'PLAN_STATE_MISMATCH')

    def test_compliant_resource_is_recorded_without_edit(self):
        plan, findings, files, state, mapping = fixture(2)
        findings[0]['evidence'][1]['value'] = 'closed'
        plan['items'][1].update(status='no_change', evidence=[findings[0]['evidence'][1]],
                                reason='already compliant', changes=[])
        proposed = files[0]['original_content'].replace('"open"', '"closed"', 1)
        self.assert_code(plan, findings, files, state, mapping, proposed)

    def test_unrelated_resource_edit_is_rejected(self):
        plan, findings, files, state, mapping = fixture()
        files[0]['original_content'] += 'resource "aws_security_group" "other" {\n  description = "safe"\n}\n'
        proposed = files[0]['original_content'].replace('"open"', '"closed"').replace('"safe"', '"changed"')
        with self.assertRaises(PatchError) as error:
            self.assert_code(plan, findings, files, state, mapping, proposed)
        self.assertEqual(error.exception.code, 'PROPOSAL_SCOPE')

    def test_unplanned_setting_inside_target_resource_is_rejected(self):
        plan, findings, files, state, mapping = fixture()
        files[0]['original_content'] = files[0]['original_content'].replace(
            '  description = "open"', '  description = "open"\n  name = "existing"')
        proposed = files[0]['original_content'].replace('"open"', '"closed"').replace(
            '"existing"', '"changed"')
        with self.assertRaises(PatchError) as error:
            self.assert_code(plan, findings, files, state, mapping, proposed)
        self.assertEqual(error.exception.code, 'PROPOSAL_PLAN_MISMATCH')

    def test_missing_operational_information_and_blanket_egress(self):
        plan, findings, files, state, mapping = fixture()
        plan['items'][0]['required_information'] = ['approved outbound destinations']
        with self.assertRaises(PatchError) as error:
            validate_plan(plan, findings, files, state, mapping)
        self.assertEqual(error.exception.code, 'MISSING_OPERATIONAL_INFO')
        plan['items'][0]['required_information'] = []
        plan['items'][0]['changes'] = [{'before': '', 'after': '  egress = []'}]
        with self.assertRaises(PatchError) as error:
            validate_plan(plan, findings, files, state, mapping)
        self.assertEqual(error.exception.code, 'UNSAFE_REMEDIATION')

    def test_security_group_value_requires_diagnosed_target(self):
        plan, findings, files, state, mapping = fixture()
        files[0]['original_content'] = files[0]['original_content'].replace(
            '  description = "open"', '  description = "open"\n  # "closed" is mentioned here')
        findings[0]['expected_value'] = 'restricted according to operations'
        with self.assertRaises(PatchError) as error:
            validate_plan(plan, findings, files, state, mapping)
        self.assertEqual(error.exception.code, 'MISSING_OPERATIONAL_INFO')

    def test_plan_and_code_agree(self):
        plan, findings, files, state, mapping = fixture(2)
        proposed = files[0]['original_content'].replace('"open"', '"closed"')
        self.assert_code(plan, findings, files, state, mapping, proposed)

    def test_one_aws_id_can_require_multiple_state_resources(self):
        plan, findings, files, state, mapping = fixture()
        files[0]['original_content'] += (
            'resource "aws_vpc_security_group_egress_rule" "outbound" {\n'
            '  from_port = 0\n}\n')
        findings[0]['expected_value'] += ' port 443'
        findings[0]['evidence'][0]['value'] = 'open FromPort=0'
        plan['items'][0]['evidence'] = [findings[0]['evidence'][0]]
        state['sg-0'].add((('aws_vpc_security_group_egress_rule', 'outbound', 'module.network'),
                           'module.network.aws_vpc_security_group_egress_rule.outbound'))
        first = {key: plan['items'][0][key] for key in ('terraform_address', 'file_path', 'changes')}
        plan['items'][0]['targets'] = [first, {
            'terraform_address': 'module.network.aws_vpc_security_group_egress_rule.outbound',
            'file_path': PATH,
            'changes': [{'before': '  from_port = 0', 'after': '  from_port = 443'}]}]
        proposed = files[0]['original_content'].replace('"open"', '"closed"').replace(
            'from_port = 0', 'from_port = 443')
        self.assert_code(plan, findings, files, state, mapping, proposed)

    def test_indexed_state_address_maps_to_its_source_block(self):
        plan, findings, files, state, mapping = fixture()
        address = 'module.network.aws_security_group.group0["primary.zone"]'
        state['sg-0'] = {(('aws_security_group', 'group0', 'module.network'), address)}
        plan['items'][0]['terraform_address'] = address
        proposed = files[0]['original_content'].replace('"open"', '"closed"')
        self.assert_code(plan, findings, files, state, mapping, proposed)

    def test_invented_cidr_port_and_reference_are_rejected(self):
        for after in ('  cidr_blocks = ["192.0.2.0/24"]',
                      '  from_port = 8443',
                      '  security_group_id = aws_security_group.invented.id'):
            with self.subTest(after=after):
                plan, findings, files, state, mapping = fixture()
                plan['items'][0]['changes'] = [{'before': '', 'after': after}]
                with self.assertRaises(PatchError) as error:
                    validate_plan(plan, findings, files, state, mapping)
                self.assertIn(error.exception.code, ('MISSING_OPERATIONAL_INFO', 'PLAN_UNGROUNDED'))

    def test_complete_status_with_truncated_file_is_rejected(self):
        plan, findings, files, state, mapping = fixture()
        with self.assertRaises(PatchError) as error:
            self.assert_code(plan, findings, files, state, mapping,
                             'resource "aws_security_group" "group0" {\n')
        self.assertEqual(error.exception.code, 'INVALID_TERRAFORM_STRUCTURE')

    def test_extra_or_missing_plan_resource_is_rejected(self):
        plan, findings, files, state, mapping = fixture(2)
        plan['items'].pop()
        with self.assertRaises(PatchError) as error:
            validate_plan(plan, findings, files, state, mapping)
        self.assertEqual(error.exception.code, 'PLAN_COVERAGE')
        plan, findings, files, state, mapping = fixture()
        invented = copy.deepcopy(plan['items'][0]); invented['resource_id'] = 'sg-invented'
        plan['items'].append(invented)
        with self.assertRaises(PatchError) as error:
            validate_plan(plan, findings, files, state, mapping)
        self.assertEqual(error.exception.code, 'PLAN_COVERAGE')

    def test_truncated_or_invalid_model_json_is_rejected(self):
        with patch('services.terraform_remediation_service.OpenAI') as client:
            response = client.return_value.responses.create.return_value
            response.status = 'incomplete'; response.output_text = '{'
            with self.assertRaises(RemediationError):
                generate_remediation_plan(findings=[], files=[], state_resources={}, rules={}, api_key='test')
            response.status = 'completed'
            with self.assertRaises(RemediationError):
                generate_remediation_plan(findings=[], files=[], state_resources={}, rules={}, api_key='test')
            response.output_text = json.dumps({'items': []})
            self.assertEqual(generate_remediation_plan(findings=[], files=[], state_resources={}, rules={}, api_key='test'),
                             {'items': []})


if __name__ == '__main__':
    unittest.main()
