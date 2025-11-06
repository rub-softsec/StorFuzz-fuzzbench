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

FROM ubuntu:focal as fuzzer_builder
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -y \
    python3 python3-pip cmake \
    llvm-12-dev clang-12 lld-12 z3 \
    git

# Download datAFLow.
RUN git clone https://github.com/HexHive/datAFLow /datAFLow && \
    cd /datAFLow && \
    git checkout f0e7c257bb11de8afe2153b18dde05736427e6ac && \
    git submodule update --init

RUN mkdir /datAFLow/build/ && \
    cd /datAFLow/build && \
    cmake .. \
        -DCMAKE_C_COMPILER=clang-12 -DCMAKE_CXX_COMPILER=clang++-12 \
        -DLLVM_DIR=$(llvm-config-12 --cmakedir) \
        -DCMAKE_BUILD_TYPE=Release && \
    make -j



FROM $parent_image

RUN apt-get update && \
    apt-get install -y \
    python3 python3-pip cmake \
    llvm-12-dev clang-12 lld-12 z3

# Download datAFLow.
COPY --from=fuzzer_builder /datAFLow/ /datAFLow/

RUN cd /datAFLow/ext/aflplusplus/utils/aflpp_driver && \
    unset CFLAGS CXXFLAGS && \
    export CC=clang-12 && \
    make && \
    cp libAFLDriver.a /

RUN cd /datAFLow/build && \
    make install
