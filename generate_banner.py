#!/usr/bin/env python3
"""Generate banner.svg from the tool's output on the sample manifest."""
import AndroidManifestExplorer as ame
from rich.console import Console

recording_console = Console(record=True, highlight=False)
ame.console = recording_console

ame.analyze_manifest("sample/AndroidManifest.xml")

recording_console.save_svg("banner.svg", title="AndroidManifestExplorer")
print("Saved banner.svg")
