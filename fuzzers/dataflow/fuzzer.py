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
"""Integration code for AFLplusplus fuzzer."""

import os
import shutil

from fuzzers.aflplusplus import fuzzer as aflpp
from fuzzers import utils

def get_stats(output_corpus, fuzzer_log):  # pylint: disable=unused-argument
    """Gets fuzzer stats for AFL."""
    return aflpp.get_stats(output_corpus, fuzzer_log)


def build():  # pylint: disable=too-many-branches,too-many-statements
    """Build benchmark."""
    # BUILD_MODES is not already supported by fuzzbench, meanwhile we provide
    # a default configuration.

    # Placeholder comment.
    build_directory = os.environ['OUT']

    os.environ['CC'] = 'dataflow-cc'
    os.environ['CXX'] = 'dataflow-c++'

    os.environ['FUZZALLOC_DEF_SENSITIVITY'] = 'array'
    os.environ['FUZZALLOC_USE_SENSITIVITY'] = 'read'
    os.environ['FUZZALLOC_USE_CAPTURE'] = 'use'
    os.environ['FUZZALLOC_INST'] = 'afl'
    
    os.environ['FUZZER_LIB'] = '/libAFLDriver.a'

    # Some benchmarks like lcms. (see:
    # https://github.com/mm2/Little-CMS/commit/ab1093539b4287c233aca6a3cf53b234faceb792#diff-f0e6d05e72548974e852e8e55dffc4ccR212)
    # fail to compile if the compiler outputs things to stderr in unexpected
    # cases. Prevent these failures by using AFL_QUIET to stop afl-clang-fast
    # from writing AFL specific messages to stderr.
    os.environ['AFL_QUIET'] = '1'
    os.environ['AFL_MAP_SIZE'] = '2621440'

    src = os.getenv('SRC')
    work = os.getenv('WORK')

    with utils.restore_directory(src), utils.restore_directory(work):
        # Restore SRC to its initial state so we can build again without any
        # trouble. For some OSS-Fuzz projects, build_benchmark cannot be run
        # twice in the same directory without this.
        utils.build_benchmark()

    shutil.copy('/datAFLow/ext/aflplusplus/afl-fuzz', build_directory)


# pylint: disable=too-many-arguments
def fuzz(input_corpus,
         output_corpus,
         target_binary,
         _flags=tuple(),
         _skip=False,
         _no_cmplog=False):  # pylint: disable=too-many-arguments
    """Run fuzzer."""
    return aflpp.fuzz(input_corpus, output_corpus, target_binary,  no_cmplog=True)
