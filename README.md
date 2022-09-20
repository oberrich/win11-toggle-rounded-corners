# Win11 Toggle Rounded Corners
A simple utility to disable window rounded corners on Windows 11

<img src="https://i.imgur.com/P0JzxSp.png">  

**Download**

Precompiled binaries are available for [**download here**](https://github.com/oberrich/win11-toggle-rounded-corners/releases) *(Some Anti-Virus products may block the access to `dwm.exe`)*.  
This program has to be run with **administrator** privileges.

To permanently disable rounded corners put the app into your auto-start.

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

