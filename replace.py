import re
path = r'c:\Netfusion\NetFusion-Agent\api\workflow\playbook_router.py'
with open(path, 'r') as f:
    code = f.read()

target1 = '''                        step_type=PlaybookStepTypeEnum(s.stepType.strip().upper()),
                        created_at=s.createdAt, description=s.description or "",
                        expected_outcome=s.expectedOutcome or "",'''
replacement1 = '''                        step_type=PlaybookStepTypeEnum(s.stepType.strip().upper()),
                        created_at=s.createdAt, description=s.description or "",
                        executor=s.executor,
                        expected_outcome=s.expectedOutcome or "",'''

code = code.replace(target1, replacement1)

with open(path, 'w') as f:
    f.write(code)
print('Replaced successfully.')
