"""
Test recursive deobfuscation of nested obfuscation layers in olevba.

Obfuscated strings found in VBA code (hex, Base64, Dridex, VBA expressions
such as StrReverse/Chr) must be decoded layer by layer: every decoded string
is scanned again for further obfuscation, until no new string is decoded.
Each URL/IOC must be reported only once, and scanning the same input twice
must yield the same analysis.

All samples are plain-text VBA files generated deterministically by this
test, so everything runs offline.
"""

import base64
import binascii
import json
import os
import shutil
import tempfile
import unittest

from tests.test_utils import call_and_capture

from oletools.olevba import VBA_Scanner


# URL hidden in the samples, only visible after decoding all layers:
URL_A = 'http://evil.example.com/payload.exe'
URL_B = 'https://cdn.badhost.example.org/update.doc'

MACRO_TEMPLATE = '''Attribute VB_Name = "Module1"
Sub AutoOpen()
    Dim s As String
    s = "%s"
    MsgBox s
End Sub
'''


def hex_encode(text):
    """Encode a string to hexadecimal, as found in obfuscated VBA code."""
    return binascii.hexlify(text.encode('ascii')).decode('ascii')


def base64_encode(text):
    """Encode a string to Base64, as found in obfuscated VBA code."""
    return base64.b64encode(text.encode('ascii')).decode('ascii')


def chr_expr(text):
    """Build a VBA Chr() concatenation expression evaluating to text."""
    return '&'.join('Chr(%d)' % ord(char) for char in text)


def build_sample_a():
    """
    URL obfuscated with 4 interleaved layers:
    hex( Base64( hex( Chr(...)&StrReverse(...) ) ) )
    Returns (macro_code, list_of_layer_strings_from_outer_to_inner).
    """
    expr = chr_expr('http:') + '&StrReverse("%s")' % URL_A[5:][::-1]
    layer_hex_inner = hex_encode(expr)
    layer_base64 = base64_encode('"%s"' % layer_hex_inner)
    layer_hex_outer = hex_encode('"%s"' % layer_base64)
    return MACRO_TEMPLATE % layer_hex_outer, \
        [layer_hex_outer, layer_base64, layer_hex_inner, expr]


def build_sample_b():
    """
    URL obfuscated with 3 interleaved layers, in a different order:
    Base64( hex( StrReverse(...) ) )
    Returns (macro_code, list_of_layer_strings_from_outer_to_inner).
    """
    expr = 'StrReverse("%s")' % URL_B[::-1]
    layer_hex = hex_encode(expr)
    layer_base64 = base64_encode('"%s"' % layer_hex)
    return MACRO_TEMPLATE % layer_base64, [layer_base64, layer_hex, expr]


def get_analysis_entries(json_output):
    """Extract the analysis entries (list of dicts) from olevba JSON output."""
    data = json.loads(json_output)
    analyses = []

    def walk(obj):
        if isinstance(obj, dict):
            if 'analysis' in obj:
                analyses.extend(obj['analysis'])
            for value in obj.values():
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)
    return analyses


class TestRecursiveDeobfuscation(unittest.TestCase):
    """Test that nested obfuscation layers are decoded recursively."""

    @classmethod
    def setUpClass(cls):
        cls.macro_a, cls.layers_a = build_sample_a()
        cls.macro_b, cls.layers_b = build_sample_b()
        # write the samples as plain-text files, to test the olevba CLI:
        cls.temp_dir = tempfile.mkdtemp(prefix='olevba_recursive_deobf_')
        cls.file_a = os.path.join(cls.temp_dir, 'sample_a.vba')
        cls.file_b = os.path.join(cls.temp_dir, 'sample_b.vba')
        with open(cls.file_a, 'w') as f:
            f.write(cls.macro_a)
        with open(cls.file_b, 'w') as f:
            f.write(cls.macro_b)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def check_ioc_found_once(self, results, url):
        """The URL must appear exactly once as an IOC in scan results."""
        ioc_values = [keyword for kw_type, keyword, description in results
                      if kw_type == 'IOC']
        self.assertIn(url, ioc_values,
                      msg='URL %r not found in IOCs: %r' % (url, ioc_values))
        self.assertEqual(ioc_values.count(url), 1,
                         msg='URL %r reported %d times, expected once'
                             % (url, ioc_values.count(url)))

    def test_scanner_decodes_all_layers(self):
        """VBA_Scanner must decode 3+ interleaved layers down to the URL."""
        for macro, layers, url in ((self.macro_a, self.layers_a, URL_A),
                                   (self.macro_b, self.layers_b, URL_B)):
            scanner = VBA_Scanner(macro)
            results = scanner.scan(include_decoded_strings=True,
                                   deobfuscate=True)
            self.check_ioc_found_once(results, url)
            # every intermediate layer must have been decoded and reported
            # (decoded strings may carry the quotes of their VBA literal):
            decoded_strings = [decoded for kw_type, decoded, encoded in results
                               if kw_type in ('Hex String', 'Base64 String',
                                              'Dridex string', 'VBA string')]
            for layer in layers[1:]:
                self.assertTrue(any(layer in decoded
                                    for decoded in decoded_strings),
                                msg='layer %r was not decoded' % layer[:40])
            self.assertIn(url, decoded_strings)

    def test_scanner_results_are_deterministic(self):
        """Scanning the same input twice must give identical results."""
        for macro in (self.macro_a, self.macro_b):
            results1 = VBA_Scanner(macro).scan(include_decoded_strings=True,
                                               deobfuscate=True)
            results2 = VBA_Scanner(macro).scan(include_decoded_strings=True,
                                               deobfuscate=True)
            self.assertEqual(results1, results2)

    def test_scanner_without_deobf_still_unwraps_hex_base64(self):
        """Hex/Base64 layers must be unwrapped even without --deobf."""
        # sample B wraps a StrReverse expression in hex and Base64: without
        # deobfuscate=True the VBA expression is not evaluated, but the hex
        # and Base64 layers must still be decoded recursively:
        scanner = VBA_Scanner(self.macro_b)
        results = scanner.scan(include_decoded_strings=True, deobfuscate=False)
        decoded_strings = [decoded for kw_type, decoded, encoded in results
                           if kw_type in ('Hex String', 'Base64 String')]
        for layer in self.layers_b[1:]:
            self.assertTrue(any(layer in decoded
                                for decoded in decoded_strings),
                            msg='layer %r was not decoded' % layer[:40])

    def test_olevba_json_reports_ioc_once(self):
        """olevba --deobf -j must report the URL exactly once as an IOC."""
        for sample_file, url in ((self.file_a, URL_A), (self.file_b, URL_B)):
            output, ret_code = call_and_capture(
                'olevba', args=(sample_file, '--deobf', '-j'))
            self.assertEqual(ret_code, 0)
            analysis = get_analysis_entries(output)
            ioc_keywords = [entry['keyword'] for entry in analysis
                            if entry['type'] == 'IOC']
            self.assertIn(url, ioc_keywords,
                          msg='URL %r not found in IOCs: %r'
                              % (url, ioc_keywords))
            self.assertEqual(ioc_keywords.count(url), 1,
                             msg='URL %r reported %d times, expected once'
                                 % (url, ioc_keywords.count(url)))

    def test_olevba_analysis_is_deterministic(self):
        """Two runs of olevba on the same input must give the same analysis."""
        output1, ret_code1 = call_and_capture(
            'olevba', args=(self.file_a, '--deobf', '-j'))
        output2, ret_code2 = call_and_capture(
            'olevba', args=(self.file_a, '--deobf', '-j'))
        self.assertEqual(ret_code1, 0)
        self.assertEqual(ret_code2, 0)
        self.assertEqual(get_analysis_entries(output1),
                         get_analysis_entries(output2))

    def test_decode_option_lists_every_layer(self):
        """olevba --deobf --decode must list each decoded layer once."""
        output, ret_code = call_and_capture(
            'olevba', args=(self.file_a, '--deobf', '--decode', '-j'))
        self.assertEqual(ret_code, 0)
        analysis = get_analysis_entries(output)
        decoded_strings = [entry['keyword'] for entry in analysis
                           if entry['type'] in ('Hex String', 'Base64 String',
                                                'Dridex string', 'VBA string')]
        # each layer must be listed exactly once (decoded strings may carry
        # the quotes of their VBA literal):
        for layer in self.layers_a[1:]:
            count = sum(1 for decoded in decoded_strings if layer in decoded)
            self.assertEqual(count, 1,
                             msg='layer %r reported %d times, expected once'
                                 % (layer[:40], count))
        self.assertEqual(decoded_strings.count(URL_A), 1)

    def test_reveal_peels_all_layers(self):
        """olevba --deobf --reveal must show the fully deobfuscated code."""
        output, ret_code = call_and_capture(
            'olevba', args=(self.file_a, '--deobf', '--reveal'))
        self.assertEqual(ret_code, 0)
        # only check the deobfuscated code section at the end of the output:
        marker = 'MACRO SOURCE CODE WITH DEOBFUSCATED VBA STRINGS'
        self.assertIn(marker, output)
        deobf_code = output.split(marker, 1)[1]
        # the URL must be visible, and the outer hex layer must be gone:
        self.assertIn(URL_A, deobf_code)
        self.assertNotIn(self.layers_a[0], deobf_code)
        self.assertNotIn(self.layers_a[1], deobf_code)


# just in case somebody calls this file as a script
if __name__ == '__main__':
    unittest.main()
