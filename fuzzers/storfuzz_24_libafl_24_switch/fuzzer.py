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

from time import time, sleep
from pathlib import Path

import json
import os
import shutil
import subprocess

from fuzzers import utils

from fuzzers.storfuzz.fuzzer import prepare_fuzz_environment, parse_stats_toml

START_TIME = time()

LIBAFL='libafl'
STORFUZZ='storfuzz'

def start_fuzzing_with_libafl(input_corpus, output_corpus, target_binary):
    """Start LibAFL and return process."""
    dictionary_path = utils.get_dictionary_path(target_binary)
    command = [target_binary]
    if dictionary_path:
        command += (['-x', dictionary_path])
    command += (['-o', output_corpus, '-i', input_corpus])
    fuzzer_env = os.environ.copy()
    fuzzer_env['LD_PRELOAD'] = '/usr/lib/x86_64-linux-gnu/libjemalloc.so.2'
    print(command)
    return subprocess.Popen(command, cwd=os.environ['OUT'], env=fuzzer_env, start_new_session=True)


def start_fuzzing_with_storfuzz(input_corpus, output_corpus, target_binary):
    """Start StorFuzz and return process."""
    original_target_binary = Path(target_binary)
    storfuzz_target_binary = original_target_binary.parent / 'storfuzz' / original_target_binary.name

    dictionary_path = utils.get_dictionary_path(target_binary)
    command = [str(storfuzz_target_binary.absolute())]
    if dictionary_path:
        command += (['-x', dictionary_path])
    elif os.path.exists('/out/storfuzz.dict'):
        command += (['-x', '/out/storfuzz.dict'])

    command += (['-o', output_corpus, '-i', input_corpus])
    fuzzer_env = os.environ.copy()
    fuzzer_env['LD_PRELOAD'] = '/usr/lib/x86_64-linux-gnu/libjemalloc.so.2'
    print(command)
    return subprocess.Popen(command, cwd=original_target_binary.parent / 'storfuzz', env=fuzzer_env, start_new_session=True)


CONFIGS = [
    {
        'fuzzer': STORFUZZ,
        'run_time': 86400,
        'start_fuzzing_func': start_fuzzing_with_storfuzz,
    },
    {
        'fuzzer': LIBAFL,
        'run_time': 86400,
        'start_fuzzing_func': start_fuzzing_with_libafl,
    }
]

PHASE_COUNTER_FILE = Path('/.storfuzz_phase_counter')

def get_phase_counter():
    if PHASE_COUNTER_FILE.exists():
        with PHASE_COUNTER_FILE.open(encoding='utf-8') as file:
            return int(file.read())
    else:
        # Assume that startup has not finished yet
        return 0


def set_phase_counter(value):
    with PHASE_COUNTER_FILE.open('w', encoding='utf-8') as file:
        file.write(f'{value}')

def get_current_fuzzer_start_func(phase_counter):
    return CONFIGS[phase_counter % len(CONFIGS)].get('start_fuzzing_func', None)

def get_current_fuzzer(phase_counter):
    return CONFIGS[phase_counter % len(CONFIGS)]['fuzzer']

def get_current_fuzzer_output_dir(phase_counter):
    return f'{get_current_fuzzer(phase_counter)}_{phase_counter}'

def get_stats(output_corpus, _fuzzer_log):
    """Gets fuzzer stats for currently running fuzzer."""

    phase_counter = get_phase_counter()

    result = {}

    stats_file = os.path.join(output_corpus, get_current_fuzzer_output_dir(phase_counter), 'stats.toml')
    stats = parse_stats_toml(stats_file)

    if stats:
        result.update({f'{key}': value for key, value in stats.items()})

    if phase_counter > 0:
        stats_file = os.path.join(output_corpus, get_current_fuzzer_output_dir(phase_counter - 1), 'stats.toml')
        stats = parse_stats_toml(stats_file)
        
        if stats:
            result.update({f'prev.{key}': value for key, value in stats.items()})


    # Report to FuzzBench the stats it accepts.
    return json.dumps(result)



def build_for_libafl():  # pylint: disable=too-many-branches,too-many-statements
    """Build benchmark."""
    new_env = os.environ.copy()
    new_env[
        'CC'] = '/libafl-stats/fuzzers/fuzzbench/target/release-fuzzbench/libafl_cc'
    new_env[
        'CXX'] = '/libafl-stats/fuzzers/fuzzbench/target/release-fuzzbench/libafl_cxx'

    new_env['ASAN_OPTIONS'] = 'abort_on_error=0:allocator_may_return_null=1'
    new_env['UBSAN_OPTIONS'] = 'abort_on_error=0'

    cflags = ['--libafl']
    cxxflags = ['--libafl', '--std=c++14']
    utils.append_flags('CFLAGS', cflags, new_env)
    utils.append_flags('CXXFLAGS', cxxflags, new_env)
    utils.append_flags('LDFLAGS', cflags, new_env)

    new_env['FUZZER_LIB'] = '/libafl-stats/stub_rt.a'
    utils.build_benchmark(new_env)

def build_for_storfuzz():  # pylint: disable=too-many-branches,too-many-statements
    """Build benchmark."""
    new_env = os.environ.copy()
    new_env[
        'CC'] = '/StorFuzz/fuzzers/storfuzz_fuzzbench_in_process/target/release/libafl_cc'
    new_env[
        'CXX'] = '/StorFuzz/fuzzers/storfuzz_fuzzbench_in_process/target/release/libafl_cxx'

    # Do NOT set this. In case of fuzzbench we want to behave like libfuzzer even at build-time
    #os.environ['CONFIGURE'] = '1'

    storfuzz_build_directory = Path(os.environ['OUT']) / 'storfuzz'
    storfuzz_build_directory.mkdir(parents=True)
    new_env['OUT'] = str(storfuzz_build_directory)

    fuzz_target = os.getenv('FUZZ_TARGET')
    if fuzz_target:
        new_env['FUZZ_TARGET'] = os.path.join(storfuzz_build_directory,
                                                os.path.basename(fuzz_target))

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

def build():
    src = os.getenv('SRC')
    work = os.getenv('WORK')

    # Restore SRC to its initial state so we can build again without any
    # trouble. For some OSS-Fuzz projects, build_benchmark cannot be run
    # twice in the same directory without this.

    with utils.restore_directory(src), utils.restore_directory(work):
        print('Building version for libafl')
        build_for_libafl()

    with utils.restore_directory(src), utils.restore_directory(work):
        print('Building version for StorFuzz')
        build_for_storfuzz()

def fuzz(input_corpus, output_corpus, target_binary):
    """Run fuzzer."""
    for config in CONFIGS:
        assert config['run_time'] > 0, f'Runtime for {config["fuzzer"]} is not set'

    next_input_corpus = Path(input_corpus)

    prepare_fuzz_environment(input_corpus)
    while True:
        phase_counter = get_phase_counter()

        run_time = CONFIGS[phase_counter % len(CONFIGS)]['run_time']

        current_output_corpus = Path(output_corpus) / get_current_fuzzer_output_dir(phase_counter)
        current_output_corpus.mkdir(parents=True, exist_ok=False)

        current_input_corpus = next_input_corpus

        proc = None

        print(f"""
=========================================================================================================
PHASE {phase_counter}: Start fuzzing with {get_current_fuzzer(phase_counter)} after {int(time() - START_TIME)} sec
=========================================================================================================
""")

        func = get_current_fuzzer_start_func(phase_counter)
        if func is not None:
            proc = func(current_input_corpus, current_output_corpus, target_binary)
        else:
            raise NotImplementedError

        assert proc.pid is not None
        pgid = os.getpgid(proc.pid)

        try:
            proc.wait(run_time)
            print('This process should not terminate. Something went wrong!')
            # Allow for an hour of debug time
            sleep(3600)
            assert False
        except subprocess.TimeoutExpired:
            os.killpg(pgid, 9)

        set_phase_counter(phase_counter + 1)

        # Ensure that we do not use metadata or lock files as input for the next stage
        next_input_corpus = Path(input_corpus).parent / f'input_{get_phase_counter()}'
        shutil.copytree(
            Path(current_output_corpus) / 'queue',
            next_input_corpus,
            ignore=shutil.ignore_patterns('.*'))
