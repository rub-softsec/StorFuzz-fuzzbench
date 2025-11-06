# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Integration code for libFuzzer fuzzer."""

import os
from pathlib import Path
import subprocess
from time import time

from fuzzers import utils

import fuzzers.storfuzz_24_libafl_24_switch.fuzzer as switch_base

START_TIME = time()

LIBFUZZER='libfuzzer'
WINGFUZZ='wingfuzz'

def _start_fuzzer(input_corpus, output_corpus, original_target_binary, phase_target_binary, extra_flags=None):
    # Manually inlined and adapted the libfuzzer run_fuzzer function
    if extra_flags is None:
        extra_flags = []

    # Seperate out corpus and crash directories as sub-directories of
    # |output_corpus| to avoid conflicts when corpus directory is reloaded.
    crashes_dir = Path(output_corpus) / 'crashes'
    output_corpus = Path(output_corpus) /'queue'
    os.makedirs(crashes_dir)
    os.makedirs(output_corpus)
    
    # Enable symbolization if needed.
    # Note: if the flags are like `symbolize=0:..:symbolize=1` then
    # only symbolize=1 is respected.
    for flag in extra_flags:
        if flag.startswith('-focus_function'):
            if 'ASAN_OPTIONS' in os.environ:
                os.environ['ASAN_OPTIONS'] += ':symbolize=1'
            else:
                os.environ['ASAN_OPTIONS'] = 'symbolize=1'
            if 'UBSAN_OPTIONS' in os.environ:
                os.environ['UBSAN_OPTIONS'] += ':symbolize=1'
            else:
                os.environ['UBSAN_OPTIONS'] = 'symbolize=1'
            break

    flags = [
        '-print_final_stats=1',
        # `close_fd_mask` to prevent too much logging output from the target.
        '-close_fd_mask=3',
        # Run in fork mode to allow ignoring ooms, timeouts, crashes and
        # continue fuzzing indefinitely.
        '-fork=1',
        '-ignore_ooms=1',
        '-ignore_timeouts=1',
        '-ignore_crashes=1',
        '-entropic=1',
        '-keep_seed=1',
        '-cross_over_uniform_dist=1',
        '-entropic_scale_per_exec_time=1',

        # Don't use LSAN's leak detection. Other fuzzers won't be using it and
        # using it will cause libFuzzer to find "crashes" no one cares about.
        '-detect_leaks=0',

        # Store crashes along with corpus for bug based benchmarking.
        f'-artifact_prefix={crashes_dir}/',
    ]
    flags += extra_flags
    if 'ADDITIONAL_ARGS' in os.environ:
        flags += os.environ['ADDITIONAL_ARGS'].split(' ')
    dictionary_path = utils.get_dictionary_path(original_target_binary)
    if dictionary_path:
        flags.append('-dict=' + dictionary_path)

    phase_target_binary = Path(phase_target_binary)

    command = [str(phase_target_binary.absolute())] + flags + [str(output_corpus), str(input_corpus)]
    print('[_start_fuzzer] Running command: ' + ' '.join(command))

    return subprocess.Popen(command, cwd=phase_target_binary.parent, start_new_session=True)

def start_fuzzing_with_wingfuzz(input_corpus, output_corpus, target_binary):
    """Start WingFuzz and return process."""
    original_target_binary = Path(target_binary)
    wingfuzz_target_binary = original_target_binary.parent / 'wingfuzz' / original_target_binary.name

    extra_flags=[
        '-fork=0', '-keep_seed=1',
        '-jobs=2147483647', '-workers=1',
        '-reload=0'
    ]

    return _start_fuzzer(input_corpus, output_corpus, target_binary, wingfuzz_target_binary, extra_flags)

def start_fuzzing_with_libfuzzer(input_corpus, output_corpus, target_binary):
    """Start libFuzzer and return process."""

    return _start_fuzzer(input_corpus, output_corpus, target_binary, target_binary, extra_flags=None)

def build_for_libfuzzer():
    """Build benchmark."""
    # With LibFuzzer we use -fsanitize=fuzzer-no-link for build CFLAGS and then
    # /usr/lib/libFuzzer.a as the FUZZER_LIB for the main fuzzing binary. This
    # allows us to link against a version of LibFuzzer that we specify.
    new_env = os.environ.copy()

    cflags = ['-fsanitize=fuzzer-no-link']
    utils.append_flags('CFLAGS', cflags, new_env)
    utils.append_flags('CXXFLAGS', cflags, new_env)

    new_env['CC'] = 'clang'
    new_env['CXX'] = 'clang++'
    new_env['FUZZER_LIB'] = '/usr/lib/libFuzzer.a'

    utils.build_benchmark(new_env)

def build_for_wingfuzz():
    """Build benchmark."""
    new_env = os.environ.copy()

    wingfuzz_build_directory = Path(os.environ['OUT']) / 'wingfuzz'
    wingfuzz_build_directory.mkdir(parents=True)
    new_env['OUT'] = str(wingfuzz_build_directory)
    
    cflags = [
        '-fsanitize=fuzzer-no-link',
        '-fno-sanitize-coverage=trace-cmp',
        '-fno-legacy-pass-manager',
        '-fpass-plugin=/LoadCmpTracer.so',
        # Hack: support non-standard build scripts ignoring LDFLAGS
        '-w',
        '-Wl,/WeakSym.o'
    ]
    utils.append_flags('CFLAGS', cflags, new_env)
    utils.append_flags('CXXFLAGS', cflags, new_env)

    new_env['CC'] = 'clang'
    new_env['CXX'] = 'clang++'
    new_env['FUZZER_LIB'] = '/libWingfuzz.a'

    utils.build_benchmark(new_env)

def build():
    """Build benchmark."""
    src = os.getenv('SRC')
    work = os.getenv('WORK')

    
    # Restore SRC to its initial state so we can build again without any
    # trouble. For some OSS-Fuzz projects, build_benchmark cannot be run
    # twice in the same directory without this.

    with utils.restore_directory(src), utils.restore_directory(work):
        print('Building version for libFuzzer')
        build_for_libfuzzer()

    with utils.restore_directory(src), utils.restore_directory(work):
        print('Building version for WingFuzz')
        build_for_wingfuzz()
    
switch_base.CONFIGS = [
    {
        'fuzzer': WINGFUZZ,
        'run_time': 3600 * 24,
        "start_fuzzing_func": start_fuzzing_with_wingfuzz,
    },
    {
        'fuzzer': LIBFUZZER,
        'run_time': 3600 * 24,
        "start_fuzzing_func": start_fuzzing_with_libfuzzer,
    }
]

def fuzz(input_corpus, output_corpus, target_binary):
    """Run fuzzer."""
    switch_base.fuzz(input_corpus, output_corpus, target_binary)