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
import subprocess

import toml
import json
import re


from fuzzers import utils

def parse_stats_toml(stats_file):
    stats = {}

    if os.path.exists(stats_file):
        try:
            stats.update(toml.load(stats_file)['client_0'])
        except Exception as exception:
            print(f'Error while parsing client part of stats.toml: {exception}')
        try:
            stats.update(toml.load(stats_file)['global'])
        except Exception as exception:
            print(f'Error while parsing global part of stats.toml: {exception}')

        ratio_regex = re.compile(r'(?P<hit_count>\d+)/(?P<total>\d+)')
        for coverage in ['data', 'edges']:
            if coverage in stats:
                match = ratio_regex.search(stats[coverage])
                if match is not None:
                    stats.update({f'{coverage}_{key}': int(match.groupdict()[key]) for key in match.groupdict()})

        # Rename to conform to fuzzbench excpectations
        stats['crashes'] = stats['objectives']
        stats['corpus_count'] = stats['corpus']
    else:
        print(f'WARNING: Could not find {stats_file}. Maybe it has not been written yet')


    return stats


def get_stats(output_corpus, _fuzzer_log):
    """Gets fuzzer stats for LibAFL-based fuzzers with stats.toml."""
    stats_file = os.path.join(output_corpus, 'stats.toml')
    stats = parse_stats_toml(stats_file)

    # Report to FuzzBench the stats it accepts.
    return json.dumps(stats)


def prepare_fuzz_environment(input_corpus):
    """Prepare to fuzz with a LibAFL-based fuzzer."""
    os.environ['ASAN_OPTIONS'] = 'abort_on_error=1:detect_leaks=0:'\
                                 'malloc_context_size=0:symbolize=0:'\
                                 'allocator_may_return_null=1:'\
                                 'detect_odr_violation=0:handle_segv=0:'\
                                 'handle_sigbus=0:handle_abort=0:'\
                                 'handle_sigfpe=0:handle_sigill=0'
    os.environ['UBSAN_OPTIONS'] =  'abort_on_error=1:'\
                                   'allocator_release_to_os_interval_ms=500:'\
                                   'handle_abort=0:handle_segv=0:'\
                                   'handle_sigbus=0:handle_sigfpe=0:'\
                                   'handle_sigill=0:print_stacktrace=0:'\
                                   'symbolize=0:symbolize_inline_frames=0'
    
    os.environ.pop('CONFIGURE', None)

    # Create at least one non-empty seed to start.
    utils.create_seed_file_for_empty_corpus(input_corpus)


def build(): # pylint: disable=too-many-branches,too-many-statements
    """Build benchmark."""
    new_env = os.environ.copy()
    new_env[
        'CC'] = '/StorFuzz/fuzzers/storfuzz_fuzzbench_in_process/target/release/libafl_cc'
    new_env[
        'CXX'] = '/StorFuzz/fuzzers/storfuzz_fuzzbench_in_process/target/release/libafl_cxx'

    # Do NOT set this. In case of fuzzbench we want to behave like libfuzzer even at build-time
    #os.environ['CONFIGURE'] = '1'

    new_env['ASAN_OPTIONS'] = 'abort_on_error=0:allocator_may_return_null=1'
    new_env['UBSAN_OPTIONS'] = 'abort_on_error=0'

    # DISABLED FOR FAIR COMPARISON
    # new_env['AFL_LLVM_DICT2FILE'] = '/out/storfuzz.dict'

    cflags = ['--libafl']
    cxxflags = ['--libafl', '--std=c++14']
    utils.append_flags('CFLAGS', cflags, new_env)
    utils.append_flags('CXXFLAGS', cxxflags, new_env)
    utils.append_flags('LDFLAGS', cflags, new_env)

    new_env['FUZZER_LIB'] = '/StorFuzz/stub_rt.a'
    utils.build_benchmark(new_env)


def fuzz(input_corpus, output_corpus, target_binary):
    """Run fuzzer."""
    prepare_fuzz_environment(input_corpus)
    dictionary_path = utils.get_dictionary_path(target_binary)
    command = [target_binary]
    if dictionary_path:
        command += (['-x', dictionary_path])
    elif os.path.exists('/out/libafl.dict'):
        command += (['-x', '/out/libafl.dict'])

    command += (['-o', output_corpus, '-i', input_corpus])
    fuzzer_env = os.environ.copy()
    fuzzer_env['LD_PRELOAD'] = '/usr/lib/x86_64-linux-gnu/libjemalloc.so.2'
    print(command)
    subprocess.check_call(command, cwd=os.environ['OUT'], env=fuzzer_env)
