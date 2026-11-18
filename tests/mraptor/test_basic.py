"""
Test basic functionality of mraptor

Covers the consistency between mraptor (quick triage) and olevba (detailed
analysis): files for which olevba finds macros or suspicious behaviour must
not be reported as clean by mraptor.
"""

import unittest
import os
from os.path import join
import shutil
import zipfile
from tempfile import mkdtemp

from tests.test_utils import DATA_BASE_DIR, call_and_capture


# mraptor exit codes, see oletools/mraptor.py:
EXIT_NO_MACRO = 0
EXIT_MACRO_OK = 2
EXIT_SUSPICIOUS = 20


class TestMraptorBasic(unittest.TestCase):
    """Tests mraptor basic functionality"""

    def test_xlm_macros_not_reported_as_clean(self):
        """XLM/Excel 4 macros in xls, xlt and slk files must be detected."""
        for filename in ('excel4_sample_macro.xls', 'excel4_sample_macro.xlt',
                         'excel4_sample_macro.slk',
                         'excel4_sample_macro_excel5_format.xls'):
            full_name = join(DATA_BASE_DIR, 'excel4-macros', filename)
            output, ret_code = call_and_capture(
                'mraptor', args=(full_name, ), accept_nonzero_exit=True)
            # those samples only display a message box, so they are not
            # suspicious, but they do contain macros (Auto_Open):
            self.assertEqual(ret_code, EXIT_MACRO_OK,
                             msg='Wrong exit code for ' + filename)
            self.assertIn('Macro OK', output)
            self.assertIn('A--', output)   # Auto_Open trigger found
            self.assertNotIn('No Macro', output)

    def test_encrypted_standard_password(self):
        """Files encrypted with the transparent password must be decrypted."""
        for suffix in ('xls', 'xlsm', 'xlsb'):
            filename = 'autostart-encrypt-standardpassword.' + suffix
            full_name = join(DATA_BASE_DIR, 'encrypted', filename)
            output, ret_code = call_and_capture(
                'mraptor', args=(full_name, ), accept_nonzero_exit=True)
            # olevba finds an Auto_Open macro in those files:
            self.assertEqual(ret_code, EXIT_MACRO_OK,
                             msg='Wrong exit code for ' + filename)
            self.assertIn('Macro OK', output)
            self.assertIn('A--', output)
            self.assertNotIn('No Macro', output)

    def test_encrypted_unknown_password_fallback(self):
        """Files encrypted with an unknown password keep the old behaviour."""
        full_name = join(DATA_BASE_DIR, 'encrypted', 'encrypted.doc')
        output, ret_code = call_and_capture(
            'mraptor', args=(full_name, ), accept_nonzero_exit=True)
        # cannot be decrypted with the default passwords: no macro can be
        # extracted, like before the decryption feature was added
        self.assertEqual(ret_code, EXIT_NO_MACRO)
        self.assertIn('No Macro', output)

    def test_zip_consistency(self):
        """Files within a zip archive must give the same result as on disk."""
        tempdir = mkdtemp(prefix='mraptor-test-')
        try:
            filenames = (
                join('excel4-macros', 'excel4_sample_macro.xls'),
                join('excel4-macros', 'excel4_sample_macro.slk'),
                join('encrypted', 'autostart-encrypt-standardpassword.xlsm'),
            )
            zip_path = join(tempdir, 'samples.zip')
            with zipfile.ZipFile(zip_path, 'w') as z:
                for relpath in filenames:
                    z.write(join(DATA_BASE_DIR, relpath),
                            arcname=os.path.basename(relpath))
            # run mraptor on the zip archive:
            output_zip, ret_code_zip = call_and_capture(
                'mraptor', args=('-z', 'infected', zip_path),
                accept_nonzero_exit=True)
            # run mraptor on each file on disk:
            for relpath in filenames:
                basename = os.path.basename(relpath)
                output_file, ret_code_file = call_and_capture(
                    'mraptor', args=(join(DATA_BASE_DIR, relpath), ),
                    accept_nonzero_exit=True)
                self.assertEqual(ret_code_file, EXIT_MACRO_OK)
                # the file within the zip must give the same result:
                self.assertIn('Macro OK', output_zip)
                self.assertIn(basename, output_zip)
                for line in output_zip.splitlines():
                    if basename in line:
                        self.assertIn('Macro OK', line)
                        break
                else:
                    self.fail('No result row for %s in zip output:\n%s'
                              % (basename, output_zip))
            self.assertEqual(ret_code_zip, ret_code_file)
        finally:
            shutil.rmtree(tempdir)

    def test_hex_hidden_keywords(self):
        """Keywords hidden in hex-encoded strings must be detected."""
        tempdir = mkdtemp(prefix='mraptor-test-')
        try:
            # "5368656C6C202263616C632E65786522" is 'Shell "calc.exe"' hex-encoded:
            suspicious_code = (
                'Sub Auto_Open()\n'
                '    Dim s As String\n'
                '    s = HexDecode("5368656C6C202263616C632E65786522")\n'
                'End Sub\n')
            sample = join(tempdir, 'hex_hidden.vba')
            with open(sample, 'w') as f:
                f.write(suspicious_code)
            output, ret_code = call_and_capture(
                'mraptor', args=(sample, ), accept_nonzero_exit=True)
            self.assertEqual(ret_code, EXIT_SUSPICIOUS)
            self.assertIn('SUSPICIOUS', output)
            self.assertIn('A-X', output)
        finally:
            shutil.rmtree(tempdir)

    def test_clean_macro_samples_stay_macro_ok(self):
        """Clean macro samples must still be reported as Macro OK."""
        tempdir = mkdtemp(prefix='mraptor-test-')
        try:
            samples = {
                # auto-exec macro without write/execute keywords:
                'clean_autoopen.vba': 'Sub Auto_Open()\n'
                                      '    MsgBox "Hello"\n'
                                      'End Sub\n',
                # hex-encoded strings decoding to benign content:
                'clean_hex.vba': 'Sub Workbook_Open()\n'
                                 '    Dim id As String\n'
                                 '    id = "4F6E652054776F2048656C6C6F"\n'
                                 '    MsgBox id\n'
                                 'End Sub\n',
                # write keyword without auto-exec trigger:
                'clean_write.vba': 'Sub Save()\n'
                                   '    ActiveDocument.Save\n'
                                   'End Sub\n',
            }
            for filename, code in samples.items():
                sample = join(tempdir, filename)
                with open(sample, 'w') as f:
                    f.write(code)
                output, ret_code = call_and_capture(
                    'mraptor', args=(sample, ), accept_nonzero_exit=True)
                self.assertEqual(ret_code, EXIT_MACRO_OK,
                                 msg='Wrong exit code for ' + filename)
                self.assertIn('Macro OK', output)
                self.assertNotIn('SUSPICIOUS', output)
        finally:
            shutil.rmtree(tempdir)


# just in case somebody calls this file as a script
if __name__ == '__main__':
    unittest.main()
