import os
from core.rule import Rule

# for django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Kunlun_M.settings')

import django

django.setup()

def test_vulnerabilities():
    vulnerabilities = Rule().vulnerabilities
    assert isinstance(vulnerabilities, list)
    assert 'SQLI' in vulnerabilities


def test_rules():
    rules = Rule().rules
    rules_list = Rule().rules()
    assert isinstance(rules, object)
    assert isinstance(rules_list, dict)
    assert isinstance(rules_list['CVI_10001'], object)