#!/usr/bin/env python3
# Author: Mateo Fumis (hackermater) - linkedin.com/in/mateo-gabriel-fumis
import xml.etree.ElementTree as ET
import argparse
import sys
from colorama import init, Fore, Style

init(autoreset=True)

ANDROID_NS = '{http://schemas.android.com/apk/res/android}'

def get_attr(element, attr_name):
    """Helper to get attributes handling the namespace"""
    return element.get(f"{ANDROID_NS}{attr_name}")

def analyze_deep_links(activity_node, full_name, package_name):
    """
    Extracts schemes, hosts, and paths from intent-filters.
    Android merges all <data> tags within a single <intent-filter>.
    """
    for intent in activity_node.findall('intent-filter'):
        schemes = []
        hosts = []
        paths = []
        
        data_tags = intent.findall('data')
        if not data_tags:
            continue

        for data in data_tags:
            s = get_attr(data, 'scheme')
            h = get_attr(data, 'host')
            p = get_attr(data, 'path') or get_attr(data, 'pathPrefix') or get_attr(data, 'pathPattern')
            
            if s: schemes.append(s)
            if h: hosts.append(h)
            if p: paths.append(p)

        schemes = list(dict.fromkeys(schemes))
        hosts = list(dict.fromkeys(hosts))
        paths = list(dict.fromkeys(paths))

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
                            print_attack(display_uri, attack_uri, package_name)
                    else:
                        print_attack(uri_with_host, uri_with_host, package_name)
            else:
                print_attack(base_uri, base_uri, package_name)

def print_attack(display_uri, attack_uri, package_name):
    """Helper to print formatted deep link findings"""
    print(f"{Fore.LIGHTGREEN_EX}    [★] DEEP LINK DETECTED: {display_uri}")
    print(f"{Fore.WHITE}    [>] Attack: adb shell am start -W -a android.intent.action.VIEW -d \"{attack_uri}\" {package_name}")

def analyze_manifest(manifest_path):
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        package_name = root.get('package')
        
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}{Style.BRIGHT}[*] AndroidManifestExplorer - Analyzing: {package_name}")
        print(f"{Fore.CYAN}{'='*70}")

        app_tag = root.find('application')

        if app_tag is not None:
            debuggable = get_attr(app_tag, 'debuggable')
            allow_backup = get_attr(app_tag, 'allowBackup')
            test_only = get_attr(app_tag, 'testOnly')
            
            if debuggable == 'true':
                print(f"{Fore.RED}[CRITICAL] debuggable='true' -> Potential data extraction and RCE.")
            
            if allow_backup == 'true':
                print(f"{Fore.YELLOW}[WARN] allowBackup='true' -> Potential data theft via 'adb backup'.")
                print(f"{Fore.WHITE}    Command: adb backup {package_name}")

            if test_only == 'true':
                print(f"{Fore.YELLOW}[INFO] testOnly='true' -> Test/Debug APK.")

        print(f"\n{Fore.CYAN}[*] Attack Surface Detected:{Style.RESET_ALL}\n")

        components = {
            'activity': {'cmd': 'am start -n', 'color': Fore.GREEN},
            'receiver': {'cmd': 'am broadcast -n', 'color': Fore.MAGENTA},
            'service':  {'cmd': 'am start-service -n', 'color': Fore.BLUE},
            'provider': {'cmd': 'content query --uri', 'color': Fore.RED}
        }

        if app_tag is not None:
            for comp_type, info in components.items():
                for node in app_tag.findall(comp_type):
                    name = get_attr(node, 'name')
                    exported = get_attr(node, 'exported')
                    permission = get_attr(node, 'permission')
                    
                    if not name: continue
                    
                    if name.startswith('.'):
                        full_name = f"{package_name}{name}"
                    elif '.' not in name:
                        full_name = f"{package_name}.{name}"
                    else:
                        full_name = name

                    has_intent_filter = node.find('intent-filter') is not None
                    is_vuln = exported == 'true' or (exported is None and has_intent_filter)

                    if is_vuln:
                        print(f"{info['color']}[+] {comp_type.upper()} EXPORTED: {full_name}")
                        
                        if permission:
                            print(f"{Fore.YELLOW}    [!] Requires permission: {permission} (Check if custom/weak)")
                        else:
                            print(f"{Fore.RED}    [!] NO PERMISSION REQUIRED (High Risk)")

                        if comp_type == 'provider':
                            authority = get_attr(node, 'authorities')
                            if authority:
                                auth_clean = authority.split(';')[0]
                                print(f"{Fore.WHITE}    [>] ADB: adb shell {info['cmd']} content://{auth_clean}/")
                                print(f"{Fore.WHITE}    [>] SQLi Test: adb shell {info['cmd']} content://{auth_clean}/ --where \"1=1\"")
                        else:
                            print(f"{Fore.WHITE}    [>] ADB: adb shell {info['cmd']} {package_name}/{full_name}")

                        if comp_type == 'activity' and has_intent_filter:
                            analyze_deep_links(node, full_name, package_name)
                        
                        print("-" * 50)

    except FileNotFoundError:
        print(f"{Fore.RED}[!] Error: File not found at {manifest_path}")
    except ET.ParseError:
        print(f"{Fore.RED}[!] Error: File is not a valid XML. Did you decompile it with APKtool/Jadx?")
    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected error: {e}")

def main():
    """Main entry point for console_scripts"""
    parser = argparse.ArgumentParser(description='AndroidManifestExplorer - Mobile Security Tool')
    parser.add_argument('-f', '--file', required=True, help='Path to AndroidManifest.xml (Decompiled with APKtool/Jadx)')
    args = parser.parse_args()
    
    analyze_manifest(args.file)

if __name__ == "__main__":
    main()
