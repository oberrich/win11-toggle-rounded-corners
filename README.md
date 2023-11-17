# Win11 Toggle Rounded Corners
A simple utility to disable window rounded corners on Windows 11

<img src="https://i.imgur.com/5HIQf7n.png">  

**Download**

An installer as well as the standalone binary for portable use can be [**downloaded here**](https://github.com/oberrich/win11-toggle-rounded-corners/releases)
The program requires **administrator** privileges. *(Some Anti-Virus products may potentially block the access to `dwm.exe`)*. 

**Build**

First clone the repo **recursive**ly
```
git clone --recursive 'https://github.com/oberrich/win11-toggle-rounded-corners.git'
```

Then simply build it with meson
```
meson setup build
meson compile -C build
```

