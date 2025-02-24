# WinNoDeco - Window Decoration Remover

⚠️ **USE AT YOUR OWN RISK** ⚠️

This is an experimental program that removes window decorations (title bars) from Windows applications. I am not a skill dev, and this software is provided as-is without any guarantees.

## Configuration

You can exclude specific programs from having their decorations removed by adding their process names to the `$USERHOME/.config/winnodeco/config.json` file:

```json
{
  "ignore_patterns": {
    "process_names": ["SearchApp", "SystemSettings", "zen", "trae", "WindowsTerminal", "notepad"],
    "window_classes": ["Shell_TrayWnd", "Windows.UI.Core.CoreWindow"]
  },
  "override": {
    "explorer": {
        "title_bar": true,
        "window_buttons": false,
        "border_radius": "Round",
        "border_visible": false
        }
    },
  "default_settings": {
    "title_bar": false,
    "window_buttons": false,
    "border_radius": "Default",
    "border_visible": false
  }
}{
  "ignore_patterns": {
    "process_names": ["SearchApp", "SystemSettings", "zen", "trae", "WindowsTerminal", "notepad"],
    "window_classes": ["Shell_TrayWnd", "Windows.UI.Core.CoreWindow"]
  },
  "override": {
    "explorer": {
        "title_bar": true,
        "window_buttons": false,
        "border_radius": "Round",
        "border_visible": false
        }
    },
  "default_settings": {
    "title_bar": false,
    "window_buttons": false,
    "border_radius": "Default",
    "border_visible": false
  }
}
```
