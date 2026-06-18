#!/usr/bin/env python3
# Author: Mateo Fumis (hackermater) - linkedin.com/in/mateo-gabriel-fumis
import xml.etree.ElementTree as ET
import argparse
import json
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.text import Text
from rich import box
from rich.markup import escape

console = Console(highlight=False)

ANDROID_NS = '{http://schemas.android.com/apk/res/android}'

DANGEROUS_PERMISSIONS = {
    'android.permission.READ_CALENDAR':               "Allows reading calendar events and details.",
    'android.permission.WRITE_CALENDAR':              "Allows creating, modifying, or deleting calendar events.",
    'android.permission.CAMERA':                      "Allows access to the device camera.",
    'android.permission.READ_CONTACTS':               "Allows reading contact information.",
    'android.permission.WRITE_CONTACTS':              "Allows creating or modifying contact information.",
    'android.permission.GET_ACCOUNTS':                "Allows access to accounts on the device.",
    'android.permission.ACCESS_FINE_LOCATION':        "Allows precise location access (GPS).",
    'android.permission.ACCESS_COARSE_LOCATION':      "Allows approximate location access (network-based).",
    'android.permission.ACCESS_BACKGROUND_LOCATION':  "Allows location access while app runs in background.",
    'android.permission.RECORD_AUDIO':                "Allows recording audio.",
    'android.permission.READ_PHONE_STATE':            "Allows reading phone state information.",
    'android.permission.READ_PHONE_NUMBERS':          "Allows reading the device's phone numbers.",
    'android.permission.CALL_PHONE':                  "Allows making phone calls directly.",
    'android.permission.READ_CALL_LOG':               "Allows reading call history logs.",
    'android.permission.WRITE_CALL_LOG':              "Allows writing call history logs.",
    'android.permission.ADD_VOICEMAIL':               "Allows adding voicemail messages.",
    'android.permission.USE_SIP':                     "Allows using SIP (Session Initiation Protocol) services.",
    'android.permission.PROCESS_OUTGOING_CALLS':      "Allows intercepting outgoing calls.",
    'android.permission.BODY_SENSORS':                "Allows access to sensor data (heart rate, etc.).",
    'android.permission.SEND_SMS':                    "Allows sending SMS messages.",
    'android.permission.RECEIVE_SMS':                 "Allows receiving SMS messages.",
    'android.permission.READ_SMS':                    "Allows reading SMS messages.",
    'android.permission.RECEIVE_WAP_PUSH':            "Allows receiving WAP push messages.",
    'android.permission.RECEIVE_MMS':                 "Allows receiving MMS messages.",
    'android.permission.READ_EXTERNAL_STORAGE':       "Allows reading files from external storage.",
    'android.permission.WRITE_EXTERNAL_STORAGE':      "Allows writing files to external storage.",
    'android.permission.MANAGE_EXTERNAL_STORAGE':     "Allows read and write access to all files within shared storage.",
    'android.permission.READ_MEDIA_IMAGES':           "Allows reading image files from shared storage.",
    'android.permission.READ_MEDIA_VIDEO':            "Allows reading video files from shared storage.",
    'android.permission.READ_MEDIA_AUDIO':            "Allows reading audio files from shared storage.",
    'android.permission.USE_BIOMETRIC':               "Allows using biometric authentication methods.",
    'android.permission.USE_FINGERPRINT':             "Allows using fingerprint for authentication.",
    'android.permission.BLUETOOTH_SCAN':              "Allows scanning for Bluetooth devices.",
    'android.permission.BLUETOOTH_CONNECT':           "Allows connecting to Bluetooth devices.",
    'android.permission.UWB_RANGING':                 "Allows ultra-wideband (UWB) distance measurement.",
    'android.permission.ACTIVITY_RECOGNITION':        "Allows recognizing physical activity/motion.",
    'android.permission.ACCEPT_HANDOVER':             "Allows accepting call handovers from other apps.",
    'android.permission.ANSWER_PHONE_CALLS':          "Allows programmatically answering incoming calls.",
    'android.permission.READ_MEDIA_VISUAL_USER_SELECTED': "Allows access to user-selected images and videos only.",
}

def get_attr(element, attr_name):
    return element.get(f"{ANDROID_NS}{attr_name}")

def analyze_deep_links(activity_node, package_name):
    results = []

    for intent in activity_node.findall('intent-filter'):
        schemes = []
        hosts = []
        paths = []
        mime_types = []

        data_tags = intent.findall('data')
        if not data_tags:
            continue

        for data in data_tags:
            s = get_attr(data, 'scheme')
            h = get_attr(data, 'host')
            p = get_attr(data, 'path') or get_attr(data, 'pathPrefix') or get_attr(data, 'pathPattern')
            m = get_attr(data, 'mimeType')

            if s: schemes.append(s)
            if h: hosts.append(h)
            if p: paths.append(p)
            if m: mime_types.append(m)

        schemes    = list(dict.fromkeys(schemes))
        hosts      = list(dict.fromkeys(hosts))
        paths      = list(dict.fromkeys(paths))
        mime_types = list(dict.fromkeys(mime_types))

        actions = [get_attr(a, 'name') for a in intent.findall('action') if get_attr(a, 'name')]
        if not actions:
            actions = ['android.intent.action.VIEW']

        if schemes:
            for action in actions:
                for s in schemes:
                    base_uri = f"{s}://"
                    if hosts:
                        for h in hosts:
                            uri_with_host = f"{base_uri}{h}"
                            if paths:
                                for p in paths:
                                    display_uri = f"{uri_with_host}{p}"
                                    clean_p = p.replace('.*', '').replace('*', '')
                                    attack_uri = f"{uri_with_host}{clean_p}"
                                    if mime_types:
                                        for m in mime_types:
                                            attack_cmd = f"adb shell am start -W -a {action} -d '{attack_uri}' -t '{m}' {package_name}"
                                            results.append({"uri": display_uri, "mime_type": m, "action": action, "attack_command": attack_cmd})
                                    else:
                                        attack_cmd = f"adb shell am start -W -a {action} -d '{attack_uri}' {package_name}"
                                        results.append({"uri": display_uri, "action": action, "attack_command": attack_cmd})
                            else:
                                if mime_types:
                                    for m in mime_types:
                                        attack_cmd = f"adb shell am start -W -a {action} -d '{uri_with_host}' -t '{m}' {package_name}"
                                        results.append({"uri": uri_with_host, "mime_type": m, "action": action, "attack_command": attack_cmd})
                                else:
                                    attack_cmd = f"adb shell am start -W -a {action} -d '{uri_with_host}' {package_name}"
                                    results.append({"uri": uri_with_host, "action": action, "attack_command": attack_cmd})
                    else:
                        if mime_types:
                            for m in mime_types:
                                attack_cmd = f"adb shell am start -W -a {action} -d '{base_uri}' -t '{m}' {package_name}"
                                results.append({"uri": base_uri, "mime_type": m, "action": action, "attack_command": attack_cmd})
                        else:
                            attack_cmd = f"adb shell am start -W -a {action} -d '{base_uri}' {package_name}"
                            results.append({"uri": base_uri, "action": action, "attack_command": attack_cmd})
        elif mime_types:
            for action in actions:
                for m in mime_types:
                    attack_cmd = f"adb shell am start -W -a {action} -t '{m}' {package_name}"
                    results.append({"mime_type": m, "action": action, "attack_command": attack_cmd})

    return results

def _cmd_text(cmd):
    """Dim monospace styling for ADB/shell commands."""
    return Text(f"$ {cmd}", style="dim cyan")

def analyze_manifest(manifest_path, output_path=None):
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        package_name = root.get('package') or "unknown.package"

        # Banner
        console.print(Panel(
            f"[bold white]Package:[/bold white] [cyan]{escape(package_name)}[/cyan]",
            title="[bold cyan]AndroidManifestExplorer[/bold cyan]",
            subtitle=f"[dim]{escape(manifest_path)}[/dim]",
            border_style="cyan",
            expand=True,
            padding=(0, 2),
        ))
        console.print()

        result = {
            "package": package_name,
            "app_flags": {},
            "dangerous_permissions": [],
            "attack_surface": []
        }

        # --- sharedUserId ---
        shared_user_id = root.get(f"{ANDROID_NS}sharedUserId")
        if shared_user_id:
            result["app_flags"]["sharedUserId"] = shared_user_id

        # --- uses-permission audit ---
        dangerous_found = []
        for perm_tag in root.findall('uses-permission'):
            perm_name = get_attr(perm_tag, 'name')
            if perm_name and perm_name in DANGEROUS_PERMISSIONS:
                dangerous_found.append(perm_name)

        if dangerous_found:
            result["dangerous_permissions"] = dangerous_found

        # --- <application> flags ---
        app_tag = root.find('application')
        debuggable = allow_backup = test_only = cleartext = network_config = None

        if app_tag is not None:
            debuggable    = get_attr(app_tag, 'debuggable')
            allow_backup  = get_attr(app_tag, 'allowBackup')
            test_only     = get_attr(app_tag, 'testOnly')
            cleartext     = get_attr(app_tag, 'usesCleartextTraffic')
            network_config = get_attr(app_tag, 'networkSecurityConfig')

            for key, val in {
                "debuggable": debuggable,
                "allowBackup": allow_backup,
                "testOnly": test_only,
                "usesCleartextTraffic": cleartext,
                "networkSecurityConfig": network_config,
            }.items():
                if val is not None:
                    result["app_flags"][key] = val

        # App Flags table
        flags_rows = []
        if shared_user_id:
            flags_rows.append(("sharedUserId", shared_user_id, "yellow", "WARN",
                               "Shares UID with other apps — check companion packages for privilege escalation."))
        if debuggable == 'true':
            flags_rows.append(("debuggable", "true", "red", "CRITICAL",
                               "Potential data extraction and RCE."))
        if allow_backup == 'true':
            flags_rows.append(("allowBackup", "true", "red", "CRITICAL",
                               f"Potential data theft via 'adb backup {escape(package_name)}'."))
        if test_only == 'true':
            flags_rows.append(("testOnly", "true", "blue", "INFO", "Test/Debug APK."))
        if cleartext == 'true':
            flags_rows.append(("usesCleartextTraffic", "true", "yellow", "WARN",
                               "App permits cleartext HTTP traffic (MITM risk)."))
        if network_config:
            flags_rows.append(("networkSecurityConfig", network_config, "yellow", "INFO",
                               "Review custom network security policy."))

        severity_order = {"CRITICAL": 0, "WARN": 1, "INFO": 2}
        flags_rows.sort(key=lambda r: severity_order.get(r[3], 99))

        if flags_rows:
            console.print(Rule("[bold cyan]App Flags[/bold cyan]", style="cyan"))
            flags_table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold white",
                                padding=(0, 1), expand=False)
            flags_table.add_column("Severity", style="bold", min_width=8)
            flags_table.add_column("Flag", style="bold white", min_width=24)
            flags_table.add_column("Value", min_width=8)
            flags_table.add_column("Note")
            for flag, value, color, severity, note in flags_rows:
                flags_table.add_row(
                    f"[{color}]{severity}[/{color}]",
                    flag,
                    f"[{color}]{escape(value)}[/{color}]",
                    note,
                )
            console.print(flags_table)

        # Dangerous permissions table
        if dangerous_found:
            console.print(Rule("[bold yellow]Dangerous Permissions[/bold yellow]", style="yellow"))
            perm_table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold white",
                               padding=(0, 1), expand=False)
            perm_table.add_column("#", style="dim", min_width=3)
            perm_table.add_column("Permission", style="yellow")
            perm_table.add_column("Description", style="dim")
            for i, p in enumerate(dangerous_found, 1):
                perm_table.add_row(str(i), p, DANGEROUS_PERMISSIONS.get(p, ""))
            console.print(perm_table)

        # Attack Surface
        console.print(Rule("[bold green]Attack Surface[/bold green]", style="green"))
        console.print()

        components = {
            'activity': {'cmd': 'am start -n',        'color': 'green',   'label': 'ACTIVITY'},
            'receiver': {'cmd': 'am broadcast -n',     'color': 'magenta', 'label': 'RECEIVER'},
            'service':  {'cmd': 'am startservice -n',  'color': 'blue',    'label': 'SERVICE'},
            'provider': {'cmd': 'content query --uri', 'color': 'red',     'label': 'PROVIDER'},
        }

        component_count = 0

        if app_tag is not None:
            for comp_type, info in components.items():
                for node in app_tag.findall(comp_type):
                    name = get_attr(node, 'name')
                    exported = get_attr(node, 'exported')
                    enabled = get_attr(node, 'enabled')
                    permission = get_attr(node, 'permission')

                    if not name: continue
                    if enabled == 'false': continue

                    if name.startswith('.'):
                        full_name = f"{package_name}{name}"
                    elif '.' not in name:
                        full_name = f"{package_name}.{name}"
                    else:
                        full_name = name

                    has_intent_filter = node.find('intent-filter') is not None
                    is_vuln = exported == 'true' or (exported is None and has_intent_filter)

                    if not is_vuln:
                        continue

                    component_count += 1
                    color = info['color']
                    label = info['label']

                    # Build panel content
                    panel_lines = Text()

                    # Permission line
                    if permission:
                        panel_lines.append("  Permission  : ", style="dim")
                        panel_lines.append(permission, style="yellow")
                        panel_lines.append("  (check if custom/weak)\n", style="dim")
                    else:
                        panel_lines.append("  Permission  : ", style="dim")
                        panel_lines.append("NONE  ", style="bold red")
                        panel_lines.append("(High Risk)\n", style="red")

                    # Provider-specific
                    entry = None
                    if comp_type == 'provider':
                        authority = get_attr(node, 'authorities')
                        grant_uri = get_attr(node, 'grantUriPermissions')

                        if grant_uri == 'true':
                            panel_lines.append("  grantUriPermissions: true  ", style="dim")
                            panel_lines.append("Any app can be granted temporary URI access.\n", style="yellow")

                        path_perms = []
                        for pp in node.findall('path-permission'):
                            path_perms.append({
                                "path": get_attr(pp, 'path') or get_attr(pp, 'pathPrefix') or get_attr(pp, 'pathPattern'),
                                "readPermission": get_attr(pp, 'readPermission'),
                                "writePermission": get_attr(pp, 'writePermission'),
                            })
                        if path_perms:
                            panel_lines.append(f"  path-permission      : {len(path_perms)} element(s)  ", style="dim")
                            panel_lines.append("Review for permission bypass.\n", style="yellow")

                        if authority:
                            auth_clean = authority.split(';')[0]
                            adb_cmd   = f"adb shell {info['cmd']} content://{auth_clean}/"
                            sqli_cmd  = f"adb shell {info['cmd']} content://{auth_clean}/ --where \"1=1\""
                            lfi_cmd   = f"adb shell content read --uri content://{auth_clean}/../../../../../../data/data/{package_name}/databases/"
                            panel_lines.append("\n")
                            panel_lines.append("  $ " + adb_cmd  + "\n", style="dim cyan")
                            panel_lines.append("  $ " + sqli_cmd + "  ", style="dim cyan")
                            panel_lines.append("[SQLi test]\n", style="dim yellow")
                            panel_lines.append("  $ " + lfi_cmd  + "  ", style="dim cyan")
                            panel_lines.append("[LFI test]\n", style="dim yellow")

                            entry = {
                                "type": comp_type, "name": full_name,
                                "permission": permission,
                                "grantUriPermissions": grant_uri,
                                "adb_command": adb_cmd,
                                "sqli_test": sqli_cmd,
                                "lfi_test": lfi_cmd,
                            }
                            if path_perms:
                                entry["path_permissions"] = path_perms
                    else:
                        adb_cmd = f"adb shell {info['cmd']} {package_name}/{full_name}"
                        panel_lines.append("\n")
                        panel_lines.append("  $ " + adb_cmd + "\n", style="dim cyan")

                        # intent-filter actions/categories
                        intent_filters = []
                        for intent in node.findall('intent-filter'):
                            actions    = [get_attr(a, 'name') for a in intent.findall('action')   if get_attr(a, 'name')]
                            categories = [get_attr(c, 'name') for c in intent.findall('category') if get_attr(c, 'name')]
                            mime_types = [get_attr(d, 'mimeType') for d in intent.findall('data') if get_attr(d, 'mimeType')]
                            if actions or categories or mime_types:
                                entry_if = {}
                                if actions:    entry_if["actions"]    = actions
                                if categories: entry_if["categories"] = categories
                                if mime_types: entry_if["mime_types"] = mime_types
                                intent_filters.append(entry_if)

                        entry = {
                            "type": comp_type, "name": full_name,
                            "permission": permission,
                            "intent_filters": intent_filters,
                            "adb_command": adb_cmd,
                        }

                        if comp_type == 'activity' and has_intent_filter:
                            deep_links = analyze_deep_links(node, package_name)
                            if deep_links:
                                entry["deep_links"] = deep_links
                                uri_links  = [dl for dl in deep_links if dl.get("uri")]
                                mime_links = [dl for dl in deep_links if not dl.get("uri")]
                                if uri_links:
                                    panel_lines.append("\n  Deep Links:\n", style="bold cyan")
                                    for dl in uri_links:
                                        panel_lines.append("  [★] ", style="bold green")
                                        panel_lines.append(dl["uri"] + "\n", style="bright_green")
                                        panel_lines.append("      $ " + dl["attack_command"] + "\n", style="dim cyan")
                                if mime_links:
                                    panel_lines.append("\n  MIME-Type Intents:\n", style="bold magenta")
                                    for dl in mime_links:
                                        panel_lines.append("  [✉] ", style="bold magenta")
                                        panel_lines.append(f"{dl['action']}  ", style="bright_magenta")
                                        panel_lines.append(f"({dl['mime_type']})\n", style="white")
                                        panel_lines.append("      $ " + dl["attack_command"] + "\n", style="dim cyan")

                    console.print(Panel(
                        panel_lines,
                        title=f"[bold {color}][{label}][/bold {color}]  [white]{escape(full_name)}[/white]",
                        border_style=color,
                        padding=(0, 1),
                        expand=True,
                    ))

                    if entry is not None:
                        result["attack_surface"].append(entry)

        if component_count == 0:
            console.print("  [dim]No exported components found.[/dim]\n")

        # Footer summary
        console.print()
        summary_parts = [f"[bold]{component_count}[/bold] component(s) found"]
        summary_parts.append(f"[bold]{len(dangerous_found)}[/bold] dangerous permission(s)")
        if output_path:
            summary_parts.append(f"output → [cyan]{output_path}[/cyan]")
        console.print(Rule(f"[dim]{' · '.join(summary_parts)}[/dim]", style="dim"))

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2)

    except FileNotFoundError:
        console.print(f"[bold red][!] Error:[/bold red] File not found: [cyan]{escape(manifest_path)}[/cyan]")
        sys.exit(1)
    except ET.ParseError:
        console.print("[bold red][!] Error:[/bold red] Not a valid XML file. Did you decompile it with APKtool/Jadx?")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red][!] Unexpected error:[/bold red] {e}")
        sys.exit(1)

def main():
    """Main entry point for console_scripts"""
    parser = argparse.ArgumentParser(description='AndroidManifestExplorer - Mobile Security Tool')
    parser.add_argument('-f', '--file', required=True, help='Path to AndroidManifest.xml (Decompiled with APKtool/Jadx)')
    parser.add_argument('-o', '--output', help='Save results to a JSON file')
    args = parser.parse_args()

    analyze_manifest(args.file, args.output)

if __name__ == "__main__":
    main()
