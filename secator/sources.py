"""Resolve a remote source (a git repository URL) to a local path.

A task that only accepts a local path (grype, trivy, gitleaks, ...) can't scan a repo
URL directly. This clones the repo shallowly to a local directory so the tool runs on
it. Tasks that handle remote URLs themselves (``URL`` in ``input_types``, e.g.
trufflehog) are left to do so. A private repo is reached by putting the credentials in
the input URL itself (``https://user:token@host/org/repo``): they are stripped from the
clone's ``.git/config`` after cloning and redacted from every message (see
``redact_url_credentials``).
"""
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

GIT_HOSTS = ('github.com', 'gitlab.com', 'bitbucket.org')


def is_git_url(value):
	"""True if ``value`` looks like a clonable git repository URL."""
	if not isinstance(value, str):
		return False
	s = value.strip()
	if s.startswith('git@') or s.startswith('ssh://'):
		return True
	if s.endswith('.git'):
		return True
	try:
		u = urlparse(s)
	except ValueError:
		return False
	if u.scheme in ('http', 'https') and u.hostname in GIT_HOSTS:
		parts = [p for p in u.path.split('/') if p]
		return len(parts) >= 2  # /owner/repo
	return False


def _repo_slug(url):
	name = re.sub(r'\.git$', '', url.rstrip('/').split('/')[-1])
	return re.sub(r'[^A-Za-z0-9._-]', '_', name) or 'repo'


# ``scheme://userinfo@`` -- the userinfo (``user``, ``token`` or ``user:token``) is a secret.
_URL_USERINFO_RE = re.compile(r'([A-Za-z][A-Za-z0-9+.-]*://)[^/\s@]+@')


def redact_url_credentials(text):
	"""Replace the userinfo of every ``scheme://user:pass@host`` URL in ``text`` with ``***``."""
	if not isinstance(text, str):
		text = str(text)
	return _URL_USERINFO_RE.sub(r'\1***@', text)


def strip_url_credentials(url):
	"""``url`` without its userinfo (``https://user:tok@host/x`` -> ``https://host/x``)."""
	return _URL_USERINFO_RE.sub(r'\1', url)


def clone_git_repo(url, dest_folder, depth=1, timeout=300):
	"""Shallow-clone ``url`` into ``dest_folder`` and return the local path.

	Args:
		url (str): Repository URL (https, or ssh via an agent). A private https repo takes
			its credentials in the URL (``https://user:token@host/org/repo``).
		dest_folder (str|Path): Parent directory the clone goes under. Callers pass a
			unique directory per input, so two repos with the same name never collide.
		depth (int): Clone depth (shallow by default).
		timeout (int): Clone timeout in seconds.

	Returns:
		str: Local path to the cloned repository.
	"""
	dest_folder = Path(dest_folder)
	dest_folder.mkdir(parents=True, exist_ok=True)
	target = dest_folder / _repo_slug(url)
	if target.exists():
		shutil.rmtree(target, ignore_errors=True)

	# GIT_TERMINAL_PROMPT=0 fails fast on a private repo with no/bad credentials instead of hanging.
	env = {**os.environ, 'GIT_TERMINAL_PROMPT': '0'}
	try:
		proc = subprocess.run(
			['git', 'clone', '--depth', str(depth), '--quiet', '--', url, str(target)],
			capture_output=True, text=True, timeout=timeout, env=env,
		)
	except subprocess.TimeoutExpired:
		# The exception's message embeds the command line, URL credentials included.
		raise RuntimeError(f'git clone of {redact_url_credentials(url)} timed out after {timeout}s') from None
	if proc.returncode != 0:
		err = redact_url_credentials((proc.stderr or '').strip())
		raise RuntimeError(f'git clone of {redact_url_credentials(url)} failed ({err})')
	clean_url = strip_url_credentials(url)
	if clean_url != url:
		# git keeps the clone URL as remote.origin.url in .git/config: drop the credentials so
		# they don't persist on disk where the scanning tool (e.g. a secret scanner) reads.
		subprocess.run(
			['git', '-C', str(target), 'remote', 'set-url', 'origin', clean_url],
			capture_output=True, text=True, timeout=60, env=env,
		)
	return str(target)


ARCHIVE_EXTENSIONS = ('.zip', '.tar', '.tar.gz', '.tgz', '.tar.bz2')


def is_gcs_url(value):
	"""True if ``value`` is a ``gs://bucket/object`` reference (an uploaded source)."""
	return isinstance(value, str) and value.startswith('gs://')


def is_archive_url(value):
	"""True if ``value`` points at a code archive that must be extracted to be scanned.

	Distinguishes an uploaded ``gs://…/foo.zip`` (extract) from a plain ``gs://`` bucket
	prefix a tool may scan natively (leave as-is).
	"""
	return isinstance(value, str) and value.lower().endswith(ARCHIVE_EXTENSIONS)


def resolve_gcs_archive(gs_url, dest_folder):
	"""Download a ``gs://`` archive and extract it, returning the local dir to scan.

	Used for uploaded code (a zip/tar stored in GCS). The archive is
	downloaded into ``dest_folder``, extracted, then removed so a tool scans the code
	rather than the archive blob. A single top-level directory (the usual archive layout)
	is returned directly.
	"""
	from secator.hooks.gcs import download_blob
	if not is_gcs_url(gs_url):
		raise ValueError(f'not a gs:// url: {gs_url}')
	bucket, _, blob = gs_url[len('gs://'):].partition('/')
	if not bucket or not blob:
		raise ValueError(f'malformed gs:// url: {gs_url}')
	dest_folder = Path(dest_folder)
	dest_folder.mkdir(parents=True, exist_ok=True)
	archive = dest_folder / (Path(blob).name or 'archive')
	download_blob(bucket, blob, str(archive))
	extract_dir = dest_folder / 'extracted'
	extract_dir.mkdir(exist_ok=True)
	shutil.unpack_archive(str(archive), str(extract_dir))
	try:
		archive.unlink()
	except OSError:
		pass
	entries = list(extract_dir.iterdir())
	if len(entries) == 1 and entries[0].is_dir():
		return str(entries[0])
	return str(extract_dir)


def demo():  # pragma: no cover - a runnable check against a tiny public repo
	import tempfile
	assert is_git_url('https://github.com/octocat/Hello-World')
	assert is_git_url('git@github.com:octocat/Hello-World.git')
	assert is_git_url('https://ghe.acme.internal/org/repo.git')
	assert not is_git_url('/tmp/code')
	assert not is_git_url('https://example.com/not-a-repo')
	d = tempfile.mkdtemp()
	p = clone_git_repo('https://github.com/octocat/Hello-World.git', d)
	assert (Path(p) / '.git').is_dir(), p
	print('ok', p)


if __name__ == '__main__':
	demo()
