This package creates the http portal on raspberry when it doesn't / can't see the wifi it can connect.
Install the package, reboot, go for http://10.24.0.1
You can add the wifi credentials and install deb package
The status page is customizable and currently used for http://Bleedio.com readers for locMESH

# build deb package

cd /opt/wifi-fallback
chmod +x packaging/build.sh
VERSION=0.4.0 packaging/build.sh

sudo dpkg -i packaging/wifi-fallback_0.4.0_$(dpkg --print-architecture).deb

# if deps missing:
sudo apt -f -y install
