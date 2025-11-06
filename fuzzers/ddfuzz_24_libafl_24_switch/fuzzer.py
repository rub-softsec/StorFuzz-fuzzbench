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
#
import os
from pathlib import Path
import subprocess

from fuzzers import utils

import fuzzers.storfuzz_24_libafl_24_switch.fuzzer as base

DDFUZZ='ddfuzz'

def get_stats(output_corpus, fuzzer_log):
    return base.get_stats(output_corpus, fuzzer_log)

def build_for_ddfuzz():
    new_env = os.environ.copy()
    new_env[
        'CC'] = '/libafl_ddfuzz/fuzzers/ddfuzz/target/release-fuzzbench/libafl_cc'
    new_env[
        'CXX'] = '/libafl_ddfuzz/fuzzers/ddfuzz/target/release-fuzzbench/libafl_cxx'

    ddfuzz_build_directory = Path(os.environ['OUT']) / 'ddfuzz'
    ddfuzz_build_directory.mkdir(parents=True)
    new_env['OUT'] = str(ddfuzz_build_directory)

    new_env['ASAN_OPTIONS'] = 'abort_on_error=0:allocator_may_return_null=1'
    new_env['UBSAN_OPTIONS'] = 'abort_on_error=0'

    cflags = ['--libafl']
    cxxflags = ['--libafl', '--std=c++14']
    utils.append_flags('CFLAGS', cflags, new_env)
    utils.append_flags('CXXFLAGS', cxxflags, new_env)
    utils.append_flags('LDFLAGS', cflags, new_env)

    new_env['FUZZER_LIB'] = '/libafl_ddfuzz/fuzzers/ddfuzz/stub_rt.a'
    utils.build_benchmark(new_env)


def build():
    src = os.getenv('SRC')
    work = os.getenv('WORK')

    # Restore SRC to its initial state so we can build again without any
    # trouble. For some OSS-Fuzz projects, build_benchmark cannot be run
    # twice in the same directory without this.

    with utils.restore_directory(src), utils.restore_directory(work):
        print('Building version for libafl')
        base.build_for_libafl()

    with utils.restore_directory(src), utils.restore_directory(work):
        print('Building version for DDFuzz')
        build_for_ddfuzz()


def start_fuzzing_with_ddfuzz(input_corpus, output_corpus, target_binary):
    """Start DDFuzz and return process."""
    original_target_binary = Path(target_binary)
    storfuzz_target_binary = original_target_binary.parent / 'ddfuzz' / original_target_binary.name

    dictionary_path = utils.get_dictionary_path(target_binary)
    command = [str(storfuzz_target_binary.absolute())]
    if dictionary_path:
        command += (['-x', dictionary_path])

    command += (['-o', output_corpus, '-i', input_corpus])
    fuzzer_env = os.environ.copy()
    fuzzer_env['LD_PRELOAD'] = '/usr/lib/x86_64-linux-gnu/libjemalloc.so.2'
    print(command)
    return subprocess.Popen(command, cwd=original_target_binary.parent / 'ddfuzz', env=fuzzer_env, start_new_session=True)
   

def fuzz(input_corpus, output_corpus, target_binary):
    return base.fuzz(input_corpus, output_corpus, target_binary)


base.CONFIGS = [
    {
        "fuzzer": DDFUZZ,
        "run_time": 3600 * 24,
        "start_fuzzing_func": start_fuzzing_with_ddfuzz
    },
    {
        "fuzzer": base.LIBAFL,
        "run_time": 3600 * 24,
        "start_fuzzing_func": base.start_fuzzing_with_libafl        
    }
]