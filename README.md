# ToxProxy

### Offline Messages for Tox

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

