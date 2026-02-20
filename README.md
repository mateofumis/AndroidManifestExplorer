# **📲 AndroidManifestExplorer**

A high-performance static analysis utility designed to automate the discovery of attack surfaces in Android applications. By parsing decompiled `AndroidManifest.xml` files, this tool identifies exposed components, security misconfigurations, and deep-link vectors, providing ready-to-use `adb` payloads for immediate dynamic verification.

## **🎯 Security Objectives**

* **Attack Surface Mapping**: Identify all exported Activities, Services, Broadcast Receivers, and Content Providers.  
* **Implicit Export Detection**: Flag components that are exported by default due to the presence of intent-filters without explicit `android:exported="false"` attributes.
* **Deep Link Analysis**: Extract URI schemes and hosts to facilitate intent-fuzzing and unauthorized navigation testing.  
* **Permission Audit**: Highlight unprotected components and evaluate the strength of defined custom permissions.  
* **Config Analysis**: Detect high-risk flags such as `debuggable="true"`, `allowBackup="true"`, and `testOnly="true"`.

## **🚀 Installation**

### Prerequisites
- Python 3.6+
- [apktool](https://apktool.org/) (for decompiling binary XML)

### **Setup**

1. Clone the repository and install the dependencies:

```bash
$: git clone https://github.com/mateofumis/AndroidManifestExplorer.git
$: cd AndroidManifestExplorer
$: pip install .
```

- Alternatively, install the requirements directly:

```bash
$: pip install -r requirements.txt
```

1. Using PyPI (Available for `pip` or `pipx`)

```bash
# with pip/pip3
$: pip install AndroidManifestExplorer
# or pipx
$: pipx install AndroidManifestExplorer
```

## **🛠 Usage Workflow**

### **1. Decompile Target APK**

The tool operates on the plain-text XML output of `apktool`.

```bash
$: apktool d target_app.apk -o output_dir
```

### **2. Execute Scan**

Run the explorer against the generated manifest:

```bash
$: AndroidManifestExplorer -f output_dir/AndroidManifest.xml
```

If running the script directly without installation:

```bash
$: python3 AndroidManifestExplorer.py -f output_dir/AndroidManifest.xml
```

## **📊 Technical Output Overview**

The tool categorizes findings by risk and generates specific `adb` commands:

* **Activities**: Generates `am start` commands.  
* **Services**: Generates `am start-service` commands.  
* **Receivers**: Generates `am broadcast` commands.  
* **Providers**: Generates `content query` commands with a default SQLi test payload (`--where "1=1"`).

### **Example Result:**

```
[+] ACTIVITY EXPORTED: com.package.name.InternalActivity  
    [!] NO PERMISSION REQUIRED (High Risk)  
    [>] ADB: adb shell am start -n com.package.name/com.package.name.InternalActivity  
    [★] DEEP LINK DETECTED: secret-app://debug_panel  
    [>] Attack: adb shell am start -W -a android.intent.action.VIEW -d "secret-app://debug_panel" com.package.name
```

### **Preview**

![Preview Image](https://github.com/mateofumis/AndroidManifestExplorer/assets/preview.png)

## **⚖️  Disclaimer**

This tool is intended for professional security research and authorized penetration testing only. Unauthorized use against systems without prior written consent is strictly prohibited and may violate local and international laws. The developer assumes no liability for misuse or damage caused by this utility.
