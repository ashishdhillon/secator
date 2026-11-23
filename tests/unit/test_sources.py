"""Source resolution helpers (no network)."""
import os
import shutil
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from secator.sources import _repo_slug, clone_git_repo, is_git_url, redact_url_credentials, strip_url_credentials


class TestSources(unittest.TestCase):

	def test_is_git_url(self):
		for ok in [
			'https://github.com/octocat/Hello-World',
			'https://github.com/octocat/Hello-World.git',
			'git@github.com:octocat/Hello-World.git',
			'https://gitlab.com/group/project',
			'https://ghe.acme.internal/org/repo.git',  # self-hosted via .git suffix
			'ssh://git@host/org/repo',
		]:
			self.assertTrue(is_git_url(ok), ok)
		for no in [
			'/tmp/code', '.', 'example.txt',
			'https://example.com/not-a-repo',  # unknown host, no .git
			'https://github.com/octocat',       # no repo part
			'http://10.0.0.1', 1234, None,
		]:
			self.assertFalse(is_git_url(no), no)

	def test_repo_slug(self):
		self.assertEqual(_repo_slug('https://github.com/octocat/Hello-World.git'), 'Hello-World')
		self.assertEqual(_repo_slug('https://gitlab.com/g/p/'), 'p')
		self.assertEqual(_repo_slug('git@github.com:o/weird name!.git'), 'weird_name_')

	def test_redact_url_credentials(self):
		self.assertEqual(
			redact_url_credentials('https://user:S3CR3T@github.com/o/r.git'), 'https://***@github.com/o/r.git')
		self.assertEqual(redact_url_credentials('https://S3CR3T@gitlab.com/g/p'), 'https://***@gitlab.com/g/p')
		self.assertEqual(
			redact_url_credentials("fatal: could not read from 'https://u:S3CR3T@h.example/o/r' and http://a:b@x/y"),
			"fatal: could not read from 'https://***@h.example/o/r' and http://***@x/y")
		self.assertEqual(redact_url_credentials(RuntimeError('https://u:p@h/x')), 'https://***@h/x')
		for clean in ['https://github.com/o/r', 'git@github.com:o/r.git', '/tmp/code', 'mail me@host.com']:
			self.assertEqual(redact_url_credentials(clean), clean)

	def test_strip_url_credentials(self):
		self.assertEqual(strip_url_credentials('https://user:S3CR3T@github.com/o/r.git'), 'https://github.com/o/r.git')
		self.assertEqual(strip_url_credentials('https://github.com/o/r.git'), 'https://github.com/o/r.git')

	def test_is_git_url_with_userinfo(self):
		self.assertTrue(is_git_url('https://user:S3CR3T@github.com/o/r'))
		self.assertTrue(is_git_url('https://S3CR3T@ghe.acme.internal/org/repo.git'))
		self.assertEqual(_repo_slug('https://user:S3CR3T@github.com/o/r.git'), 'r')

	def test_clone_with_userinfo(self):
		url = 'https://user:S3CR3T@github.com/o/r.git'
		with mock.patch('secator.sources.subprocess.run') as run:
			run.return_value = SimpleNamespace(returncode=0, stderr='')
			path = clone_git_repo(url, self._tmp())
		clone_call, set_url_call = run.call_args_list
		# git gets the credentialed URL to clone ...
		self.assertEqual(clone_call.args[0][-2:], [url, path])
		self.assertEqual(clone_call.kwargs['env']['GIT_TERMINAL_PROMPT'], '0')
		# ... then the credentials are dropped from the clone's .git/config.
		self.assertEqual(
			set_url_call.args[0], ['git', '-C', path, 'remote', 'set-url', 'origin', 'https://github.com/o/r.git'])

	def test_clone_without_userinfo_skips_set_url(self):
		with mock.patch('secator.sources.subprocess.run') as run:
			run.return_value = SimpleNamespace(returncode=0, stderr='')
			clone_git_repo('https://github.com/o/r.git', self._tmp())
		self.assertEqual(run.call_count, 1)

	def test_clone_error_redacts_credentials(self):
		url = 'https://user:S3CR3T@github.com/o/r.git'
		with mock.patch('secator.sources.subprocess.run') as run:
			run.return_value = SimpleNamespace(returncode=128, stderr=f"fatal: repository '{url}' not found")
			with self.assertRaises(RuntimeError) as ctx:
				clone_git_repo(url, self._tmp())
		self.assertNotIn('S3CR3T', str(ctx.exception))
		self.assertIn('https://***@github.com/o/r.git', str(ctx.exception))

	def test_clone_timeout_redacts_credentials(self):
		url = 'https://user:S3CR3T@github.com/o/r.git'
		with mock.patch('secator.sources.subprocess.run', side_effect=subprocess.TimeoutExpired(['git', 'clone', url], 1)):
			with self.assertRaises(RuntimeError) as ctx:
				clone_git_repo(url, self._tmp(), timeout=1)
		self.assertNotIn('S3CR3T', str(ctx.exception))
		self.assertIsNone(ctx.exception.__cause__)
		self.assertTrue(ctx.exception.__suppress_context__)

	def test_clone_real_repo_strips_credentials_from_git_config(self):
		"""End-to-end against a local bare repo: userinfo is accepted and not persisted."""
		if not shutil.which('git'):
			self.skipTest('git not installed')
		src = self._tmp()
		env = {
			**os.environ,
			'GIT_AUTHOR_NAME': 'a', 'GIT_AUTHOR_EMAIL': 'a@b', 'GIT_COMMITTER_NAME': 'a', 'GIT_COMMITTER_EMAIL': 'a@b',
		}
		subprocess.run(['git', 'init', '-q', src], check=True, env=env)
		subprocess.run(['git', '-C', src, 'commit', '-q', '--allow-empty', '-m', 'x'], check=True, env=env)
		# file:// ignores userinfo, so this exercises the real clone + set-url path offline.
		path = clone_git_repo(f'file://user:S3CR3T@{src}', self._tmp())
		with open(f'{path}/.git/config') as f:
			config = f.read()
		self.assertNotIn('S3CR3T', config)
		self.assertIn(f'url = file://{src}', config)

	def _tmp(self):
		d = tempfile.mkdtemp()
		self.addCleanup(shutil.rmtree, d, ignore_errors=True)
		return d

	def _resolve(self, inputs, **run_opts):
		from secator.runners._base import Runner
		fake = SimpleNamespace(
			inputs=list(inputs), run_opts=run_opts, reports_folder=self._tmp(), _print=mock.Mock(),
			config=SimpleNamespace(type='task', input_types=['path']),
		)
		with mock.patch('secator.sources.clone_git_repo', return_value='/cloned') as clone:
			Runner._resolve_sources(fake)
		return fake, clone

	def test_resolve_clones_userinfo_url_and_redacts_messages(self):
		url = 'https://user:S3CR3T@github.com/a/x.git'
		fake, clone = self._resolve([url, '/local/path'])
		self.assertEqual(clone.call_args.args[0], url)
		self.assertEqual(fake.inputs, ['/cloned', '/local/path'])
		printed = str(fake._print.call_args_list)
		self.assertNotIn('S3CR3T', printed)
		self.assertIn('https://***@github.com/a/x.git', printed)

	def test_resolve_clone_failure_redacts_warning(self):
		from secator.runners._base import Runner
		url = 'https://user:S3CR3T@github.com/a/x.git'
		fake = SimpleNamespace(
			inputs=[url], run_opts={}, reports_folder=self._tmp(), _print=mock.Mock(),
			config=SimpleNamespace(type='task', input_types=['path']),
		)
		with mock.patch('secator.sources.clone_git_repo', side_effect=RuntimeError(f'boom {url}')):
			Runner._resolve_sources(fake)
		self.assertEqual(fake.inputs, [url])  # left as-is for validation to report
		printed = str(fake._print.call_args_list)
		self.assertNotIn('S3CR3T', printed)
		self.assertIn('https://***@github.com/a/x.git', printed)

	def test_resolve_skips_url_accepting_task(self):
		from secator.runners._base import Runner
		fake = SimpleNamespace(
			inputs=['https://github.com/a/x.git'], run_opts={}, reports_folder=self._tmp(), _print=mock.Mock(),
			config=SimpleNamespace(type='task', input_types=['url', 'path']),
		)
		with mock.patch('secator.sources.clone_git_repo') as clone:
			Runner._resolve_sources(fake)
		clone.assert_not_called()

	def test_gcs_and_archive_detection(self):
		from secator.sources import is_gcs_url, is_archive_url
		assert is_gcs_url('gs://bucket/sources/x/app.zip')
		assert not is_gcs_url('https://github.com/a/b')
		assert is_archive_url('gs://bucket/x/app.zip')
		assert is_archive_url('App.TAR.GZ') and is_archive_url('x.tgz')
		assert not is_archive_url('gs://bucket/some/prefix')  # a bucket, not an archive
		assert not is_archive_url('x.py')


if __name__ == '__main__':
	unittest.main()
