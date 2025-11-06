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
import fuzzers.storfuzz_24_libafl_24_switch.fuzzer as base

base.CONFIGS = [
    {
        "fuzzer": base.LIBAFL,
        "run_time": 3600 * 24,
        "start_fuzzing_func": base.start_fuzzing_with_libafl,
    },
    {
        "fuzzer": base.LIBAFL,
        "run_time": 3600 * 24,
        "start_fuzzing_func": base.start_fuzzing_with_libafl,
    }
]


def get_stats(output_corpus, fuzzer_log):
    return base.get_stats(output_corpus, fuzzer_log)

def build():
    return base.build_for_libafl()

def fuzz(input_corpus, output_corpus, target_binary):
    return base.fuzz(input_corpus, output_corpus, target_binary)