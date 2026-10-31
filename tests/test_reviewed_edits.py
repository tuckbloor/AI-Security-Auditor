import hashlib
import pytest
from pathlib import Path
from reviewed_edits import make_proposal, apply_proposal, source_excerpt, locate_source


def test_proposal_never_writes_until_approved(tmp_path):
    root=tmp_path/'code';root.mkdir()
    f=root/'handler.py';f.write_bytes(b'value = 1\nprint(value)\n')
    proposed=make_proposal(root,'handler.py',1,'value = 2')
    assert f.read_text() == 'value = 1\nprint(value)\n'
    assert '-value = 1' in proposed.diff and '+value = 2' in proposed.diff
    backup=apply_proposal(root,proposed,tmp_path/'backups')
    assert f.read_text() == 'value = 2\nprint(value)\n'
    assert backup.read_bytes() == b'value = 1\nprint(value)\n'



@pytest.mark.parametrize(
    ('original', 'expected'),
    [
        (b'value = 1\nprint(value)\n', b'value = 2\nprint(value)\n'),
        (b'value = 1\r\nprint(value)\r\n', b'value = 2\r\nprint(value)\r\n'),
        (b'value = 1\r\nprint(value)\n', b'value = 2\r\nprint(value)\n'),
        (b'value = 1', b'value = 2'),
    ],
    ids=['LF', 'CRLF', 'mixed-line-endings', 'no-trailing-newline'],
)
def test_backup_preserves_exact_original_bytes(tmp_path, original, expected):
    root = tmp_path / 'code'
    root.mkdir()
    source = root / 'handler.py'
    source.write_bytes(original)
    change = make_proposal(root, 'handler.py', 1, 'value = 2')
    assert source.read_bytes() == original  # Proposal does not write.
    backup = apply_proposal(root, change, tmp_path / 'backups')
    assert backup.read_bytes() == original
    assert source.read_bytes() == expected

def test_prevent_stale_change(tmp_path):
    root=tmp_path/'code';root.mkdir()
    file=root/'route.php';file.write_text('<?php\n$x = 1;\n')
    proposal=make_proposal(root,'route.php',2,'$x = 2;')
    file.write_text('<?php\n$x = 100;\n')
    with pytest.raises(ValueError,match='changed'):
        apply_proposal(root,proposal,tmp_path/'backup')
    assert '$x = 100' in file.read_text()


def test_cannot_escape_root(tmp_path):
    root=tmp_path/'code';root.mkdir()
    with pytest.raises(ValueError,match='Unsafe'):
        locate_source(root,'../secret.py')
    with pytest.raises(ValueError,match='Unsafe'):
        locate_source(root,str(tmp_path/'secret.py'))


def test_nonexistent_file_blocked(tmp_path):
    with pytest.raises((ValueError,FileNotFoundError)):
        make_proposal(tmp_path,'resources/views/missing.php',1,'hello')


def test_secret_files_blocked(tmp_path):
    (tmp_path/'.env').write_text('X=1')
    with pytest.raises(ValueError,match='file type'):
        locate_source(tmp_path,'.env')


def test_python_syntax_must_parse(tmp_path):
    (tmp_path/'app.py').write_text('print(1)\n')
    with pytest.raises(ValueError,match='parse as Python'):
        make_proposal(tmp_path,'app.py',1,'for x in :')


def test_line_endings_preserved(tmp_path):
    (tmp_path/'a.php').write_bytes(b'<?php\r\nfoo();\r\n')
    proposal=make_proposal(tmp_path,'a.php',2,'bar();')
    apply_proposal(tmp_path,proposal,tmp_path.parent/('backup-'+tmp_path.name))
    assert (tmp_path/'a.php').read_bytes() == b'<?php\r\nbar();\r\n'


def test_no_change_does_not_create_backup(tmp_path):
    (tmp_path/'a.php').write_text('<?php\nfoo();\n')
    with pytest.raises(ValueError,match='does not change'):
        make_proposal(tmp_path,'a.php',2,'foo();')


def test_backups_cannot_be_in_project(tmp_path):
    (tmp_path/'a.php').write_text('<?php\nfoo();\n')
    proposal=make_proposal(tmp_path,'a.php',2,'bar();')
    with pytest.raises(ValueError,match='outside'):
        apply_proposal(tmp_path,proposal,tmp_path/'backup')


def test_symlinks_blocked(tmp_path):
    root=tmp_path/'src';root.mkdir()
    outside=tmp_path/'other.php';outside.write_text('<?php')
    try: (root/'linked.php').symlink_to(outside)
    except (OSError,NotImplementedError): pytest.skip('No symlink support')
    with pytest.raises(ValueError,match='symbolic'):
        locate_source(root,'linked.php')


def test_excerpt_hash_matches_source(tmp_path):
    f=tmp_path/'a.php';f.write_bytes(b'<?php\nhello();\n')
    excerpt,digest=source_excerpt(tmp_path,'a.php',2)
    assert 'hello();' in excerpt
    assert digest == hashlib.sha256(f.read_bytes()).hexdigest()
