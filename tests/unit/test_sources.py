"""Source resolution helpers (no network)."""
import base64
import unittest
from types import SimpleNamespace
from unittest import mock

from secator.sources import _repo_slug, _token_auth_env, clone_git_repo, git_url_host, is_git_url


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

	def test_token_auth_env_scoped_to_origin(self):
		env = _token_auth_env('https://ghe.acme.internal:8443/org/repo.git', 'SECRET')
		self.assertEqual(env['GIT_CONFIG_KEY_0'], 'http.https://ghe.acme.internal:8443/.extraHeader')
		self.assertEqual(env['GIT_CONFIG_VALUE_0'], 'Authorization: Basic ' + base64.b64encode(b'SECRET:').decode())
		env = _token_auth_env('https://gitlab.com/g/p.git', 'oauth2:SECRET')
		self.assertEqual(env['GIT_CONFIG_VALUE_0'], 'Authorization: Basic ' + base64.b64encode(b'oauth2:SECRET').decode())

	def test_clone_keeps_token_out_of_argv(self):
		with mock.patch('secator.sources.subprocess.run') as run:
			run.return_value = SimpleNamespace(returncode=0, stderr='')
			clone_git_repo('https://github.com/o/r.git', self._tmp(), token='SECRET')
		args, kwargs = run.call_args
		self.assertNotIn('SECRET', ' '.join(args[0]))
		self.assertIn('http.https://github.com/.extraHeader', kwargs['env'].values())

	def test_clone_refuses_token_over_plain_http(self):
		with mock.patch('secator.sources.subprocess.run') as run:
			with self.assertRaises(RuntimeError):
				clone_git_repo('http://git.example.com/o/r.git', self._tmp(), token='SECRET')
		run.assert_not_called()

	def test_git_url_host(self):
		self.assertEqual(git_url_host('https://GitHub.com/o/r'), 'github.com')
		self.assertEqual(git_url_host('git@gitlab.com:o/r.git'), 'gitlab.com')
		self.assertEqual(git_url_host('ssh://git@host.example/o/r'), 'host.example')

	def _tmp(self):
		import shutil
		import tempfile
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

	def _tokens(self, clone):
		return [c.kwargs['token'] for c in clone.call_args_list]

	def test_token_sent_to_matching_host(self):
		_, clone = self._resolve(
			['https://github.com/a/x.git', 'https://GitHub.com/b/y.git'], git_token='T', git_token_host='github.com')
		self.assertEqual(self._tokens(clone), ['T', 'T'])

	def test_token_host_is_case_insensitive(self):
		_, clone = self._resolve(['https://github.com/a/x.git'], git_token='T', git_token_host='GitHub.COM')
		self.assertEqual(self._tokens(clone), ['T'])

	def test_token_not_sent_to_other_host(self):
		_, clone = self._resolve(['https://gitlab.com/a/x.git'], git_token='T', git_token_host='github.com')
		self.assertEqual(self._tokens(clone), [None])

	def test_token_no_subdomain_or_suffix_match(self):
		_, clone = self._resolve(
			['https://api.github.com/a/x.git', 'https://evilgithub.com/a/x.git', 'https://github.com.evil.io/a/x.git'],
			git_token='T', git_token_host='github.com')
		self.assertEqual(self._tokens(clone), [None, None, None])

	def test_token_mixed_inputs(self):
		_, clone = self._resolve(
			['https://github.com/a/x.git', 'https://gitlab.com/b/y.git', 'https://github.com/c/z.git'],
			git_token='T', git_token_host='github.com')
		self.assertEqual(self._tokens(clone), ['T', None, 'T'])

	def test_token_not_sent_over_http_on_matching_host(self):
		fake, clone = self._resolve(
			['http://git.example.com/a/x.git', 'git@git.example.com:a/x.git'],
			git_token='S3CR3T', git_token_host='git.example.com')
		self.assertEqual(self._tokens(clone), [None, None])
		fake._print.assert_called()
		self.assertNotIn('S3CR3T', str(fake._print.call_args_list))  # never logged

	def test_token_without_host_is_refused(self):
		with self.assertRaisesRegex(ValueError, 'git_token_host'):
			self._resolve(['https://github.com/a/x.git'], git_token='T')

	def test_host_without_token_clones_unauthenticated(self):
		_, clone = self._resolve(['https://github.com/a/x.git'], git_token_host='github.com')
		self.assertEqual(self._tokens(clone), [None])

	def test_normalize_git_host(self):
		from secator.sources import normalize_git_host
		self.assertIsNone(normalize_git_host(None))
		self.assertIsNone(normalize_git_host(''))
		self.assertEqual(normalize_git_host(' GitHub.com. '), 'github.com')
		for bad in ['https://github.com', 'github.com/org', 'github.com:443', 'user@github.com', '*.github.com', 'a..b']:
			with self.assertRaises(ValueError, msg=bad):
				normalize_git_host(bad)

	def test_no_env_token_fallback(self):
		with mock.patch.dict('os.environ', {'SECATOR_GIT_TOKEN': 'ENV'}):
			_, clone = self._resolve(['https://github.com/a/x.git'])
		self.assertIsNone(clone.call_args.kwargs['token'])

	def test_git_token_is_redacted(self):
		from secator.runners._base import REDACTED_OPT_VALUE, Runner
		fake = SimpleNamespace(run_opts={'git_token': 'T', 'depth': 1}, sensitive_opt_names=set())
		opts = Runner.resolved_opts.fget(fake)
		self.assertEqual(opts['git_token'], REDACTED_OPT_VALUE)
		self.assertEqual(opts['depth'], 1)

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
