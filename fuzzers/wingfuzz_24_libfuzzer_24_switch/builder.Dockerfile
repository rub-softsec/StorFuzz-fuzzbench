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

ARG parent_image
FROM gcr.io/oss-fuzz-base/base-builder@sha256:87ca1e9e19235e731fac8de8d1892ebe8d55caf18e7aa131346fc582a2034fdd AS fuzzer_builder

# Build libFuzzer
RUN git clone https://github.com/llvm/llvm-project.git /llvm-project && \
    cd /llvm-project && \
    git checkout 5cda4dc7b4d28fcd11307d4234c513ff779a1c6f && \
    cd compiler-rt/lib/fuzzer && \
    (for f in *.cpp; do \
      clang++ -stdlib=libc++ -fPIC -O2 -std=c++11 $f -c & \
    done && wait) && \
    ar r libFuzzer.a *.o


# Build wingfuzz
RUN git clone https://github.com/WingTecherTHU/wingfuzz /wingfuzz
RUN cd /wingfuzz && git checkout 6ef3281f145fa1839df0f46c38b348ec9d93b0e2 && \
    ./build.sh && cd instrument && ./build.sh && clang -c WeakSym.c
    


FROM $parent_image

COPY --from=fuzzer_builder /llvm-project /llvm-project
RUN cp /llvm-project/compiler-rt/lib/fuzzer/libFuzzer.a /usr/lib

COPY --from=fuzzer_builder /wingfuzz /wingfuzz
RUN cp /wingfuzz/libFuzzer.a /libWingfuzz.a && \
    cp /wingfuzz/instrument/WeakSym.o / && \
    cp /wingfuzz/instrument/LoadCmpTracer.so /