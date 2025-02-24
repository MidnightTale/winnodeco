# WinNoDeco - Window Decoration Remover

⚠️ **USE AT YOUR OWN RISK** ⚠️

This is an experimental program that removes window decorations (title bars) from Windows applications. I am not a skill dev, and this software is provided as-is without any guarantees.

## Configuration

You can exclude specific programs from having their decorations removed by adding their process names to the `$USERHOME/.config/winnodeco/config.json` file:

```json
{
    "excluded_processes": ["explorer.exe", "taskmanager.exe"]
}
```
