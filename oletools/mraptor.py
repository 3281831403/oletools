#!/usr/bin/env python
"""
mraptor.py - MacroRaptor

MacroRaptor is a script to parse OLE and OpenXML files such as MS Office
documents (e.g. Word, Excel), to detect malicious macros.

Supported formats:
- Word 97-2003 (.doc, .dot), Word 2007+ (.docm, .dotm)
- Excel 97-2003 (.xls), Excel 2007+ (.xlsm, .xlsb)
- PowerPoint 97-2003 (.ppt), PowerPoint 2007+ (.pptm, .ppsm)
- Word/PowerPoint 2007+ XML (aka Flat OPC)
- Word 2003 XML (.xml)
- Word/Excel Single File Web Page / MHTML (.mht)
- Publisher (.pub)

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

MacroRaptor is part of the python-oletools package:
http://www.decalage.info/python/oletools
"""

# === LICENSE ==================================================================

# MacroRaptor is copyright (c) 2016-2021 Philippe Lagadec (http://www.decalage.info)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#------------------------------------------------------------------------------
# CHANGELOG:
# 2016-02-23 v0.01 PL: - first version
# 2016-02-29 v0.02 PL: - added Workbook_Activate, FileSaveAs
# 2016-03-04 v0.03 PL: - returns an exit code based on the overall result
# 2016-03-08 v0.04 PL: - collapse long lines before analysis
# 2016-08-31 v0.50 PL: - added macro trigger InkPicture_Painted
# 2016-09-05       PL: - added Document_BeforeClose keyword for MS Publisher (.pub)
# 2016-10-25       PL: - fixed print for Python 3
# 2016-12-21 v0.51 PL: - added more ActiveX macro triggers
# 2017-03-08       PL: - fixed absolute imports
# 2018-05-25 v0.53 PL: - added Word/PowerPoint 2007+ XML (aka Flat OPC) issue #283
# 2019-04-04 v0.54 PL: - added ExecuteExcel4Macro, ShellExecuteA, XLM keywords
# 2019-11-06 v0.55 PL: - added SetTimer
# 2020-04-20 v0.56 PL: - added keywords RUN and CALL for XLM macros (issue #562)
# 2021-04-14       PL: - added Workbook_BeforeClose (issue #518)

__version__ = '0.56.2'

#------------------------------------------------------------------------------
# TODO:


#--- IMPORTS ------------------------------------------------------------------

import sys, optparse, re, os
from io import BytesIO
from tempfile import mkstemp

import olefile

# IMPORTANT: it should be possible to run oletools directly as scripts
# in any directory without installing them with pip or setup.py.
# In that case, relative imports are NOT usable.
# And to enable Python 2+3 compatibility, we need to use absolute imports,
# so we add the oletools parent folder to sys.path (absolute+normalized path):
_thismodule_dir = os.path.normpath(os.path.abspath(os.path.dirname(__file__)))
# print('_thismodule_dir = %r' % _thismodule_dir)
_parent_dir = os.path.normpath(os.path.join(_thismodule_dir, '..'))
# print('_parent_dir = %r' % _thirdparty_dir)
if not _parent_dir in sys.path:
    sys.path.insert(0, _parent_dir)

from oletools.thirdparty.xglob import xglob
from oletools.thirdparty.tablestream import tablestream

from oletools import olevba
from oletools import crypto
from oletools.olevba import TYPE2TAG
from oletools.common.log_helper import log_helper

# === LOGGING =================================================================

# a global logger object used for debugging:
log = log_helper.get_or_create_silent_logger('mraptor')


#--- CONSTANTS ----------------------------------------------------------------

# URL and message to report issues:
# TODO: make it a common variable for all oletools
URL_ISSUES = 'https://github.com/decalage2/oletools/issues'
MSG_ISSUES = 'Please report this issue on %s' % URL_ISSUES

# 'AutoExec', 'AutoOpen', 'Auto_Open', 'AutoClose', 'Auto_Close', 'AutoNew', 'AutoExit',
# 'Document_Open', 'DocumentOpen',
# 'Document_Close', 'DocumentBeforeClose', 'Document_BeforeClose',
# 'DocumentChange','Document_New',
# 'NewDocument'
# 'Workbook_Open', 'Workbook_Close',
# *_Painted such as InkPicture1_Painted
# *_GotFocus|LostFocus|MouseHover for other ActiveX objects
# reference: http://www.greyhathacker.net/?p=948

# TODO: check if line also contains Sub or Function
re_autoexec = re.compile(r'(?i)\b(?:Auto(?:Exec|_?Open|_?Close|Exit|New)' +
                         r'|Document(?:_?Open|_Close|_?BeforeClose|Change|_New)' +
                         r'|NewDocument|Workbook(?:_Open|_Activate|_Close|_BeforeClose)' +
                         r'|\w+_(?:Painted|Painting|GotFocus|LostFocus|MouseHover' +
                         r'|Layout|Click|Change|Resize|BeforeNavigate2|BeforeScriptExecute' +
                         r'|DocumentComplete|DownloadBegin|DownloadComplete|FileDownload' +
                         r'|NavigateComplete2|NavigateError|ProgressChange|PropertyChange' +
                         r'|SetSecureLockIcon|StatusTextChange|TitleChange|MouseMove' +
                         r'|MouseEnter|MouseLeave|OnConnecting))|Auto_Ope\b')
# TODO: "Auto_Ope" is temporarily here because of a bug in plugin_biff, which misses the last byte in "Auto_Open"...

# MS-VBAL 5.4.5.1 Open Statement:
RE_OPEN_WRITE = r'(?:\bOpen\b[^\n]+\b(?:Write|Append|Binary|Output|Random)\b)'

re_write = re.compile(r'(?i)\b(?:FileCopy|CopyFile|Kill|CreateTextFile|'
    + r'VirtualAlloc|RtlMoveMemory|URLDownloadToFileA?|AltStartupPath|WriteProcessMemory|'
    + r'ADODB\.Stream|WriteText|SaveToFile|SaveAs|SaveAsRTF|FileSaveAs|MkDir|RmDir|SaveSetting|SetAttr)\b|' + RE_OPEN_WRITE)

# MS-VBAL 5.2.3.5 External Procedure Declaration
RE_DECLARE_LIB = r'(?:\bDeclare\b[^\n]+\bLib\b)'

re_execute = re.compile(r'(?i)\b(?:Shell|CreateObject|GetObject|SendKeys|RUN|CALL|'
    + r'MacScript|FollowHyperlink|CreateThread|ShellExecuteA?|ExecuteExcel4Macro|EXEC|REGISTER|SetTimer)\b|' + RE_DECLARE_LIB)


# === CLASSES =================================================================

class Result_NoMacro(object):
    exit_code = 0
    color = 'green'
    name = 'No Macro'


class Result_NotMSOffice(object):
    exit_code = 1
    color = 'green'
    name = 'Not MS Office'


class Result_MacroOK(object):
    exit_code = 2
    color = 'cyan'
    name = 'Macro OK'


class Result_Error(object):
    exit_code = 10
    color = 'yellow'
    name = 'ERROR'


class Result_Suspicious(object):
    exit_code = 20
    color = 'red'
    name = 'SUSPICIOUS'


class MacroRaptor(object):
    """
    class to scan VBA macro code to detect if it is malicious
    """
    def __init__(self, vba_code):
        """
        MacroRaptor constructor
        :param vba_code: string containing the VBA macro code
        """
        # collapse long lines first
        self.vba_code = olevba.vba_collapse_long_lines(vba_code)
        self.autoexec = False
        self.write = False
        self.execute = False
        self.flags = ''
        self.suspicious = False
        self.autoexec_match = None
        self.write_match = None
        self.execute_match = None
        self.matches = []

    def scan(self):
        """
        Scan the VBA macro code to detect if it is malicious
        :return:
        """
        # The code is scanned as is, but also after decoding the obfuscated
        # strings it may contain (hex, base64, dridex), so that keywords
        # hidden within encoded strings are detected too, like olevba does:
        codes_to_scan = [self.vba_code]
        strreverse = 'strreverse' in self.vba_code.lower()
        code_hex = ''
        for encoded, decoded in olevba.detect_hex_strings(self.vba_code):
            code_hex += '\n' + decoded
            if strreverse:
                # StrReverse after hex decoding:
                codes_to_scan.append(decoded[::-1])
                # StrReverse before hex decoding:
                codes_to_scan.append(olevba.bytes2str(olevba.binascii.unhexlify(encoded[::-1])))
        codes_to_scan.append(code_hex)
        for encoded, decoded in olevba.detect_base64_strings(self.vba_code):
            codes_to_scan.append(decoded)
        for encoded, decoded in olevba.detect_dridex_strings(self.vba_code):
            codes_to_scan.append(decoded)
        for code in codes_to_scan:
            if not code:
                continue
            if not self.autoexec:
                m = re_autoexec.search(code)
                if m is not None:
                    self.autoexec = True
                    self.autoexec_match = m.group()
                    self.matches.append(m.group())
            if not self.write:
                m = re_write.search(code)
                if m is not None:
                    self.write = True
                    self.write_match = m.group()
                    self.matches.append(m.group())
            if not self.execute:
                m = re_execute.search(code)
                if m is not None:
                    self.execute = True
                    self.execute_match = m.group()
                    self.matches.append(m.group())
            if self.autoexec and self.write and self.execute:
                break
        if self.autoexec and (self.execute or self.write):
            self.suspicious = True

    def get_flags(self):
        flags = ''
        flags += 'A' if self.autoexec else '-'
        flags += 'W' if self.write else '-'
        flags += 'X' if self.execute else '-'
        return flags


# === FILE ANALYSIS ===========================================================

def is_encrypted(filename, data):
    """
    Check if a file is encrypted, whether it is on disk or in memory
    (e.g. a file within a zip archive).

    :param str filename: path of the file on disk, or its name within a container
    :param bytes data: file contents in memory, or None if the file is on disk
    :return: bool
    """
    try:
        if data is not None:
            # file in memory: only OLE files may be encrypted (OpenXML files
            # are encrypted within an OLE container):
            if not olefile.isOleFile(BytesIO(data)):
                return False
            return crypto.is_encrypted(olefile.OleFileIO(BytesIO(data)))
        return crypto.is_encrypted(filename)
    except Exception:
        log.debug('Error while checking if the file is encrypted', exc_info=True)
        return False


def decrypt_file(filename, data):
    """
    Attempt to decrypt an encrypted file using the default passwords
    (e.g. "VelvetSweatshop"), like olevba does.

    :param str filename: path of the file on disk, or its name within a container
    :param bytes data: file contents in memory, or None if the file is on disk
    :return: path of the temporary file with decrypted contents, or None if
             decryption failed
    """
    temp_encrypted_file = None
    try:
        if data is not None:
            # crypto.decrypt only works with files on disk, so the data must
            # be written to a temporary file first:
            fd, temp_encrypted_file = mkstemp(prefix='mraptor-encrypted-')
            with os.fdopen(fd, 'wb') as file_handle:
                file_handle.write(data)
            source = temp_encrypted_file
        else:
            source = filename
        decrypted_file, _ = crypto.decrypt(source, crypto.DEFAULT_PASSWORDS)
        return decrypted_file
    except Exception:
        log.debug('Failed to decrypt the file', exc_info=True)
        return None
    finally:
        if temp_encrypted_file is not None:
            try:
                os.unlink(temp_encrypted_file)
            except Exception:
                pass


def analyze_file(filename, data, container, crypto_nesting=0):
    """
    Open a file with VBA_Parser, detect the presence of VBA and Excel 4/XLM
    macros, and extract the macro source code.

    If the file is encrypted, a decryption with the default passwords is
    attempted first (like olevba does), so that files protected with a
    transparent/standard password are analyzed like their decrypted content.

    :param str filename: path of the file on disk, or its name within a container
    :param bytes data: file contents in memory, or None if the file is on disk
    :param str container: path of the container (zip archive) if any
    :param int crypto_nesting: current level of nesting for encrypted files
    :return: tuple (filetype, contains_macros, macro_code)
    """
    # if the file is encrypted, try to decrypt it with the default passwords
    # first, so that the analysis is performed on the decrypted content:
    if crypto_nesting < crypto.MAX_NESTING_DEPTH and is_encrypted(filename, data):
        decrypted_file = decrypt_file(filename, data)
        if decrypted_file is not None:
            try:
                log.info('File is encrypted, analyzing the decrypted content')
                return analyze_file(decrypted_file, None, container or filename,
                                    crypto_nesting + 1)
            finally:
                try:
                    os.unlink(decrypted_file)
                except Exception:
                    pass
    vba_parser = olevba.VBA_Parser(filename=filename, data=data, container=container)
    try:
        filetype = TYPE2TAG[vba_parser.type]
        # detect both VBA and Excel 4/XLM macros, so that the quick triage
        # is consistent with the detailed analysis done by olevba:
        if not vba_parser.detect_macros():
            return filetype, False, ''
        return filetype, True, vba_parser.get_vba_code_all_modules()
    finally:
        vba_parser.close()


# === MAIN ====================================================================

def main():
    """
    Main function, called when olevba is run from the command line
    """
    DEFAULT_LOG_LEVEL = "warning" # Default log level

    usage = 'usage: mraptor [options] <filename> [filename2 ...]'
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-r", action="store_true", dest="recursive",
                      help='find files recursively in subdirectories.')
    parser.add_option("-z", "--zip", dest='zip_password', type='str', default=None,
                      help='if the file is a zip archive, open all files from it, using the provided password (requires Python 2.6+)')
    parser.add_option("-f", "--zipfname", dest='zip_fname', type='str', default='*',
                      help='if the file is a zip archive, file(s) to be opened within the zip. Wildcards * and ? are supported. (default:*)')
    parser.add_option('-l', '--loglevel', dest="loglevel", action="store", default=DEFAULT_LOG_LEVEL,
                            help="logging level debug/info/warning/error/critical (default=%default)")
    parser.add_option("-m", '--matches', action="store_true", dest="show_matches",
                      help='Show matched strings.')

    # TODO: add logfile option

    (options, args) = parser.parse_args()

    # Print help if no arguments are passed
    if len(args) == 0:
        print('MacroRaptor %s - http://decalage.info/python/oletools' % __version__)
        print('This is work in progress, please report issues at %s' % URL_ISSUES)
        print(__doc__)
        parser.print_help()
        print('\nAn exit code is returned based on the analysis result:')
        for result in (Result_NoMacro, Result_NotMSOffice, Result_MacroOK, Result_Error, Result_Suspicious):
            print(' - %d: %s' % (result.exit_code, result.name))
        sys.exit()

    # print banner with version
    print('MacroRaptor %s - http://decalage.info/python/oletools' % __version__)
    print('This is work in progress, please report issues at %s' % URL_ISSUES)

    log_helper.enable_logging(level=options.loglevel)
    # enable logging in the modules:
    olevba.enable_logging()

    t = tablestream.TableStream(style=tablestream.TableStyleSlim,
            header_row=['Result', 'Flags', 'Type', 'File'],
            column_width=[10, 5, 4, 56])

    exitcode = -1
    global_result = None
    # TODO: handle errors in xglob, to continue processing the next files
    for container, filename, data in xglob.iter_files(args, recursive=options.recursive,
                                                      zip_password=options.zip_password, zip_fname=options.zip_fname):
        # ignore directory names stored in zip files:
        if container and filename.endswith('/'):
            continue
        full_name = '%s in %s' % (filename, container) if container else filename
        # try:
        #     # Open the file
        #     if data is None:
        #         data = open(filename, 'rb').read()
        # except:
        #     log.exception('Error when opening file %r' % full_name)
        #     continue
        if isinstance(data, Exception):
            result = Result_Error
            t.write_row([result.name, '', '', full_name],
                        colors=[result.color, None, None, None])
            t.write_row(['', '', '', str(data)],
                        colors=[None, None, None, result.color])
        else:
            filetype = '???'
            try:
                filetype, contains_macros, vba_code_all_modules = analyze_file(
                    filename, data, container)
            except Exception as e:
                # log.error('Error when parsing VBA macros from file %r' % full_name)
                # TODO: distinguish actual errors from non-MSOffice files
                result = Result_Error
                t.write_row([result.name, '', filetype, full_name],
                            colors=[result.color, None, None, None])
                t.write_row(['', '', '', str(e)],
                            colors=[None, None, None, result.color])
                continue
            if contains_macros:
                mraptor = MacroRaptor(vba_code_all_modules)
                mraptor.scan()
                if mraptor.suspicious:
                    result = Result_Suspicious
                else:
                    result = Result_MacroOK
                t.write_row([result.name, mraptor.get_flags(), filetype, full_name],
                            colors=[result.color, None, None, None])
                if mraptor.matches and options.show_matches:
                    t.write_row(['', '', '', 'Matches: %r' % mraptor.matches])
            else:
                result = Result_NoMacro
                t.write_row([result.name, '', filetype, full_name],
                            colors=[result.color, None, None, None])
        if result.exit_code > exitcode:
            global_result = result
            exitcode = result.exit_code

    log_helper.end_logging()
    print('')
    print('Flags: A=AutoExec, W=Write, X=Execute')
    print('Exit code: %d - %s' % (exitcode, global_result.name))
    sys.exit(exitcode)

if __name__ == '__main__':
    main()

# Soundtrack: "Dark Child" by Marlon Williams
