from pathlib import Path
import pytest
from auditor import scan_project, detect_frameworks, findings_as_dicts, allowed_file


def test_detects_known_issues_and_not_dependencies(tmp_path):
    (tmp_path / 'app.py').write_text('requests.get(url, verify=False)\nsubprocess.run(cmd, shell=True)\n')
    dep = tmp_path / 'vendor'; dep.mkdir()
    (dep / 'test.php').write_text('eval($data);\n')
    result = scan_project(tmp_path)
    assert result.scanned_files == 1
    assert {f.rule for f in result.findings} == {'TLS verification disabled', 'Shell command execution'}
    assert not result.truncated


def test_laravel_framework_recognition(tmp_path):
    (tmp_path / 'artisan').touch()
    (tmp_path / 'composer.json').write_text('{"require":{"laravel/framework":"^13.0"}}')
    (tmp_path / 'package.json').write_text('{"dependencies":{"vue":"^3.0.0"}}')
    assert {'Laravel', 'Vue', 'PHP / Composer'} <= set(detect_frameworks(tmp_path))


def test_detects_django(tmp_path):
    (tmp_path / 'requirements.txt').write_text('Django==5.1\n')
    assert 'Django' in detect_frameworks(tmp_path)


def test_skips_test_fixtures_and_symlinks_by_default(tmp_path):
    src = tmp_path / 'src'; src.mkdir()
    (src / 'app.py').write_text('eval(untrusted)\n')
    for name in ('tests', 'sample-project'):
        folder=tmp_path/name;folder.mkdir()
        (folder/'test.py').write_text('eval(untrusted)\n')
    scan = scan_project(tmp_path)
    assert scan.scanned_files == 1
    scan2 = scan_project(tmp_path, include_test_files=True)
    assert scan2.scanned_files == 3


def test_never_returns_source_secrets(tmp_path):
    (tmp_path / 'config.py').write_text('password = "very-secret-token"\n')
    findings = scan_project(tmp_path).findings
    assert len(findings) == 1
    assert 'very-secret-token' not in str(findings_as_dicts(findings))


def test_findings_have_category_and_id(tmp_path):
    (tmp_path / 'app.php').write_text('unserialize($untrusted);\n')
    item = scan_project(tmp_path).findings[0]
    assert item.category == 'Deserialization'
    assert len(item.id) == 14


def test_skips_comment_only_matches(tmp_path):
    (tmp_path / 'app.py').write_text('# eval(request)\nprint("hello")\n')
    assert scan_project(tmp_path).findings == []


def test_limits_source_files(tmp_path):
    for i in range(4):
        (tmp_path / f'{i}.py').write_text('print(1)\n')
    result = scan_project(tmp_path, max_files=2)
    assert result.scanned_files == 2
    assert result.truncated


def test_limits_findings(tmp_path):
    (tmp_path / 'a.py').write_text('eval(x)\n'*8)
    result = scan_project(tmp_path, max_findings=3)
    assert len(result.findings) == 3
    assert result.truncated


def test_missing_folder(tmp_path):
    with pytest.raises(ValueError): scan_project(tmp_path / 'missing')


def test_env_file_ignored(tmp_path):
    (tmp_path / '.env').write_text('password = "very-secret-token"\n')
    assert scan_project(tmp_path).scanned_files == 0
    assert not allowed_file(tmp_path/'.env')


def test_blade_xss_detection(tmp_path):
    templates=tmp_path/'resources'/'views';templates.mkdir(parents=True)
    (templates / 'home.blade.php').write_text('<div>{!! $unsafe !!}</div>\n')
    items=scan_project(tmp_path).findings
    assert len(items) == 1
    assert items[0].category == 'Cross-site scripting'


def test_sql_pattern(tmp_path):
    (tmp_path/'OrdersController.php').write_text('DB::select("select * from x where id = $id");\n')
    assert scan_project(tmp_path).findings[0].category == 'SQL injection'


def test_linked_folder_ignored(tmp_path):
    outside=tmp_path.parent/('outsider-'+tmp_path.name);outside.mkdir()
    (outside/'bad.py').write_text('eval(input())\n')
    try: (tmp_path/'linked').symlink_to(outside, target_is_directory=True)
    except (OSError,NotImplementedError): pytest.skip('No symlink support')
    assert scan_project(tmp_path).findings == []
