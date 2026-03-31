# ToxProxy

### Offline Messages for Tox

ToxProxy provides offline message relay functionality for the Tox messaging protocol, acting as a persistent proxy that buffers messages when your primary device is offline and delivers them when you reconnect.<br>

ToxProxy is designed to run continuously on a server or always-on device, configured to accept control commands only from a specific Master device's public key.<br>

#### Key Features

- **Message Buffering**: Stores messages when your "Master" device (typically a mobile phone) is offline
- **Push Notifications**: Can wake up your Master device when new messages arrive via configurable push servers
- **Cross-Platform**: Builds on Linux, macOS, and Windows (via cross-compilation)
- **SQLite Storage**: Uses a custom C ORM (csorma) for persistent message storage

#### Technical Stack

- **Core**: C implementation using toxcore amalgamation for Tox protocol support
- **Dependencies**: libsodium (encryption), libcurl (push notifications), pthread (threading)
- **Database**: SQLite with custom csorma ORM for schema management
- **Build**: Requires openjdk-17-jdk for code generation during build process
<br>

[![Liberapay](https://img.shields.io/liberapay/goal/zoff.svg?logo=liberapay)](https://liberapay.com/zoff/donate)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/zoff99/ToxProxy)

<img height="300" src="https://raw.githubusercontent.com/zoff99/ToxProxy/zoff99/tweaks_001/pix/toxproxy_001_medium.jpg"></img><br>

##### building on Linux and macOS

```bash
# install libsodium-dev libcurl4-gnutls-dev openjdk-17-jdk (depending on your OS)
git clone https://github.com/zoff99/ToxProxy
cd ToxProxy/src/
make
ls -al ToxProxy
# openjdk-17-jdk is not needed to run ToxProxy, only for building it
```

##### build for Windows on a Linux machine

```bash
# install docker.io rsync (depending on your Linux Distro)
git clone https://github.com/zoff99/ToxProxy
cd ToxProxy/.localrun/
./docker_it_win.sh build
./docker_it_win.sh
ls -al windows_ub20/artefacts/ToxProxy.exe
# copy ToxProxy.exe to your windows machine
```

<br>
Any use of this project's code by GitHub Copilot, past or present, is done
without our permission.  We do not consent to GitHub's use of this project's
code in Copilot.
<br>
No part of this work may be used or reproduced in any manner for the purpose of training artificial intelligence technologies or systems.

