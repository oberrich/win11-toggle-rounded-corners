# win11-toggle-rounded-corners
A simple utility that does **NOT** patch dwm (uDWM.dll) in order to disable window rounded corners on Windows 11

No system files are being replaced so you **won't** brick your system. All this tool really does is setting a bool inside the heap of the Desktop Window Manager (DWM) or to be more precise inside the `udwm.dll`s singleton instance of `CDesktopManager`.

**Demonstration**  
<br><img src="https://i.imgur.com/u2HnnAL.gif">  

**Download**  

Precompiled binaries are available [**here**](https://github.com/oberrich/win11-toggle-rounded-corners/releases) *(Some Anti-Virus products may block the access to `dwm.exe` in which case you have to disable them temporarily)*.  

To permanently disable rounded corners put the app into your auto-start (Task Manager > Startup apps > Run new task > `path/to/win11-toggle-rounded-edges.exe`).  

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

If you find any bugs or issues feel free to [open an issue](https://github.com/oberrich/win11-toggle-rounded-corners/issues/new).
