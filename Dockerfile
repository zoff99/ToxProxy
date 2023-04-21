# ============================================================================
# ToxProxy
# Copyright (C) 2019 - 2020 Zoff <zoff@zoff.cc>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# ============================================================================
#
# --------------------------------------------------------
#
# command to build:             docker build -t zoff99/toxproxy .
# command to prep :             mkdir -p ./dockerdata/
# command to run  :             docker run --rm --volume=$(pwd)/dockerdata:/home/pi/src/db -d zoff99/toxproxy
#
# --------------------------------------------------------

FROM ubuntu:18.04
LABEL maintainer="zoff99"
LABEL vendor1="https://github.com/zoff99/ToxProxy"

WORKDIR /home/pi/
COPY src /home/pi/src/

ENV _INST_ /home/pi/inst
ENV _SRC_ /home/pi/src

RUN apt-get update && \
            apt-get install -y --force-yes --no-install-recommends \
            pkg-config \
            gcc libc6-dev \
            libcurl4-gnutls-dev \
            zip grep file ca-certificates \
            bc wget rsync \
            ssh gzip tar unzip \
            coreutils && \
            apt-get install -y --force-yes --no-install-recommends \
            libsodium-dev

RUN         cd /home/pi/src/ ; \
            export CFLAGS=" -Wall -Wextra -Wno-unused-parameter -flto -fPIC -std=gnu99 -O3 -g -fstack-protector-all " ; \
            gcc $CFLAGS \
                ToxProxy.c \
                -l:libsodium.a \
                -lcurl \
                -lm \
                -ldl \
                -lpthread \
                -o ToxProxy || exit 1

ENTRYPOINT pwd ; cd /home/pi/src/ ; while [ true ]; do ./ToxProxy ; sleep 5 ; done
