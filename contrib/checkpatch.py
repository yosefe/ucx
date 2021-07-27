#!/usr/bin/env python

import re
import sys
import argparse
import subprocess
import functools
import os


re_trailing_w = re.compile(r'\s+$')
def check_trailing_w(file_name, line):
    stripped = line.rstrip()
    if stripped != line:
        return "trailing witespace", line.rstrip()
    else:
        return None, None

#
# line check function should accept a line and return either (None, None) if the
# line is correct, or a (error, fixed_line) if the line contains an error.
#
line_checks = [
    check_trailing_w
    ]

def checks_lines(file_name, file_text, verbose):
    num_errors = 0
    lines = file_text.splitlines()
    for lineno in range(1, len(lines) + 1):
        line = lines[lineno - 1]
        # For each line, check all checks
        for check in line_checks:
            (error, fixed_line) = check(file_name,line)
            if fixed_line:
                if error:
                    print("%s:%d: %s" % (file_name, lineno, error))
                lines[lineno - 1] = fixed_line
                num_errors += 1
    if num_errors > 0:
        return None, "\n".join(lines)
    else:
        return None, None

def check_trailing_nl(file_name, file_text, verbose):
    if file_text and file_text[-1] != '\n':
        return "no newline at end of file", file_text + '\n'
    else:
        return None, None

#
# file check function should accept file text and return either (None, None) if
# the file is correct, or a (error, fixed_text) if the line contains an error.
#
file_checks = [
    checks_lines,
    check_trailing_nl
    ]

def check_file(file_name, fix, verbose):
    if not os.path.isfile(file_name):
        return 0
    if verbose:
        print("checking %s" % file_name)
    num_errors = 0
    giveup = False
    with open(file_name, mode=(fix and 'r+' or 'r')) as f:
        # Go over all lines
        file_text = f.read()
        # For each line, check all checks
        for check in file_checks:
            error, fixed_text = check(file_name, file_text, verbose)
            if fixed_text:
                if error:
                    print("%s: %s" % (file_name, error))
                file_text = fixed_text
                num_errors += 1
        if fix and (num_errors > 0):
            f.seek(0)
            f.truncate()
            f.write(file_text)
    if num_errors == 0:
        return 0
    else:
        return -1

def parse_args():
    parser = argparse.ArgumentParser(
        description="Check commit range for trivial errors")
    parser.add_argument("--fix", action="store_true", default=False,
                        help="Automatically correct problems")
    parser.add_argument('--diff', action='store', nargs='?',
                        help="operate on git diff", default=argparse.SUPPRESS)
    parser.add_argument('-v', action='store_true')
    parser.add_argument('file', action='store', nargs='*',
                        help="files to check", default=[])
    return parser.parse_args()

def main():
    options = parse_args()
    file_names = options.file
    if 'diff' in options:
        git_command = ['git', 'diff', '--name-only']
        if options.diff:
            git_command.append(options.diff)
        file_names += [fn.decode('utf8')
                       for fn in subprocess.check_output(git_command).splitlines()]
    if not file_names:
        print("no changed files")
        return 0

    results = [check_file(fn, options.fix, options.v) for fn in file_names]
    return functools.reduce(min, results, 0)

rc = main()
sys.exit(rc)