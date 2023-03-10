#!/bin/bash -eu

# make-in-docker.sh
#
# Purpose
# -------
# This runs make in a Docker container.
#
# See also:
# - scripts/docker_env.sh for general Docker prerequisites and other information.
#
# WARNING: the Dockerfile used by this script is no longer maintained! See
# https://github.com/Mbed-TLS/mbedtls-test/blob/master/README.md#quick-start
# for the set of Docker images we use on the CI.

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

source tests/scripts/docker_env.sh

run_in_docker make $@
