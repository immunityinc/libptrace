;
; Copyright (C) 2019, Cyxtera Cybersecurity, Inc.  All rights reserved.
;
; This library is free software; you can redistribute it and/or modify it
; under the terms of the GNU Lesser General Public License version 2.1 as
; published by the Free Software Foundation.
;
; This library is distributed in the hope that it will be useful, but WITHOUT
; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
; FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
; version 2.1 for more details.
;
; You should have received a copy of the GNU Lesser General Public License
; version 2.1 along with this library; if not, write to the Free Software
; Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301,
; USA.
;
; THE CODE AND SCRIPTS POSTED ON THIS WEBSITE ARE PROVIDED ON AN "AS IS" BASIS
; AND YOUR USE OF SUCH CODE AND/OR SCRIPTS IS AT YOUR OWN RISK.  CYXTERA
; DISCLAIMS ALL EXPRESS AND IMPLIED WARRANTIES, EITHER IN FACT OR BY OPERATION
; OF LAW, STATUTORY OR OTHERWISE, INCLUDING, BUT NOT LIMITED TO, ALL
; WARRANTIES OF MERCHANTABILITY, TITLE, FITNESS FOR A PARTICULAR PURPOSE,
; NON-INFRINGEMENT, ACCURACY, COMPLETENESS, COMPATABILITY OF SOFTWARE OR
; EQUIPMENT OR ANY RESULTS TO BE ACHIEVED THEREFROM.  CYXTERA DOES NOT WARRANT
; THAT SUCH CODE AND/OR SCRIPTS ARE OR WILL BE ERROR-FREE.  IN NO EVENT SHALL
; CYXTERA BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, RELIANCE,
; EXEMPLARY, PUNITIVE OR CONSEQUENTIAL DAMAGES, OR ANY LOSS OF GOODWILL, LOSS
; OF ANTICIPATED SAVINGS, COST OF PURCHASING REPLACEMENT SERVICES, LOSS OF
; PROFITS, REVENUE, DATA OR DATA USE, ARISING IN ANY WAY OUT OF THE USE AND/OR
; REDISTRIBUTION OF SUCH CODE AND/OR SCRIPTS, REGARDLESS OF THE LEGAL THEORY
; UNDER WHICH SUCH LIABILITY IS ASSERTED AND REGARDLESS OF WHETHER CYXTERA HAS
; BEEN ADVISED OF THE POSSIBILITY OF SUCH LIABILITY.
;
; libptrace-setup.nsi
;
; Dedicated to Yuzuyu Arielle Huizer.
;
; Author: Ronald Huizer <ronald@immunityinc.com>
;
!ifdef USE64
    !define LIBRARY_X64
!endif
!include "LogicLib.nsh"
!include "Library.nsh"
!include "MUI2.nsh"
!include "StrFunc.nsh"
!include "WordFunc.nsh"

; Product definitions.
!define PRODUCT_NAME        "libptrace"
!define PRODUCT_PUBLISHER   "Immunity Inc."

!define PYTHON_PACKAGES     "lib\site-packages"
!define PYTHON_SCRIPTS      "scripts"

; MUI settings.
!define MUI_ICON                        "nsis/theme/immunity_logo.ico"
!define MUI_UNICON                      "nsis/theme/immunity_logo.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT
!define MUI_HEADERIMAGE_BITMAP          "nsis/theme/immunity_header.bmp"
!define MUI_HEADERIMAGE_UNBITMAP        "nsis/theme/immunity_header.bmp"
!define MUI_LICENSEPAGE_RADIOBUTTONS
!define MUI_WELCOMEFINISHPAGE
!define MUI_WELCOMEFINISHPAGE_BITMAP    "nsis/theme/immunity_wizard.bmp"

; Start Menu Folder Page Configuration
!define MUI_STARTMENUPAGE_DEFAULTFOLDER "${PRODUCT_PUBLISHER}\${PRODUCT_NAME}"
!define MUI_STARTMENUPAGE_REGISTRY_ROOT "HKLM"
!define MUI_STARTMENUPAGE_REGISTRY_KEY "Software\${PRODUCT_PUBLISHER}\${PRODUCT_NAME}"
!define MUI_STARTMENUPAGE_REGISTRY_VALUENAME "StartMenuFolder"

Name    "libptrace"

!ifdef USE64
    InstallDir "$PROGRAMFILES64\${PRODUCT_PUBLISHER}\${PRODUCT_NAME}"
    outfile "libptrace-setup64.exe"
!else
    InstallDir "$PROGRAMFILES\${PRODUCT_PUBLISHER}\${PRODUCT_NAME}"
    outfile "libptrace-setup32.exe"
!endif

RequestExecutionLevel admin

; Variables.
Var Python27Packages
Var Python37Packages
Var StartMenuFolder

; Page hierarchy.
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "COPYING.LESSER"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_STARTMENU Application $StartMenuFolder
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

; Descriptions on the component selection page.
LangString DESC_SecPtrace    ${LANG_ENGLISH} "Install libptrace."
LangString DESC_SecPython27  ${LANG_ENGLISH} "Install Python 2.7 bindings."
LangString DESC_SecPython37  ${LANG_ENGLISH} "Install Python 3.7 bindings."

Section "Python 2.7" SecPython27
    WriteRegStr HKLM "Software\${PRODUCT_PUBLISHER}\${PRODUCT_NAME}" "Python27Location" $Python27Packages
    CreateDirectory $Python27Packages
    SetOutPath      $Python27Packages
    File "/oname=_ptrace.pyd" "python/libpy27ptrace.dll"
SectionEnd

Section "Python 3.7" SecPython37
    WriteRegStr HKLM "Software\${PRODUCT_PUBLISHER}\${PRODUCT_NAME}" "Python37Location" $Python37Packages
    CreateDirectory $Python37Packages
    SetOutPath      $Python37Packages
    File "/oname=_ptrace.pyd" "python/libpy37ptrace.dll"
SectionEnd

Section "libptrace" SecPtrace
    SetOverwrite try

    WriteRegStr HKLM "Software\${PRODUCT_PUBLISHER}\${PRODUCT_NAME}" "InstallLocation" $INSTDIR

    !insertmacro InstallLib DLL NOTSHARED REBOOT_NOTPROTECTED src/libptrace.dll $SYSDIR\libptrace.dll $SYSDIR

    SetOutPath $INSTDIR
    File "python/scripts/core.py"
    File "python/scripts/events.py"
    File "python/scripts/heaptrace.py"
    File "python/scripts/inject.py"
    File "python/scripts/keylogger.py"
    File "python/scripts/module_exports.py"
    File "python/scripts/modules.py"
    File "python/scripts/processes.py"
    File "python/scripts/registers.py"
    File "python/scripts/regtrace.py"
    File "python/scripts/remote_break.py"
    File "python/scripts/remote_thread.py"
    File "AUTHORS"
    File "ChangeLog"
    File "COPYING"
    File "COPYING.LESSER"
    File "README.md"

    WriteUninstaller "$INSTDIR\uninstall.exe"

    !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
        CreateDirectory "$SMPROGRAMS\$StartMenuFolder\"
        CreateShortCut  "$SMPROGRAMS\$StartMenuFolder\uninstall.lnk" "$INSTDIR\uninstall.exe"
    !insertmacro MUI_STARTMENU_WRITE_END
SectionEnd

function .onInit
    ; Filter out the '.' so we do not pass it to the filesystem or the related
    ; InstallLocation in the registry.  It will however be used for the name
    ; of the registry key.
    ${StrFilter} "$INSTDIR" "" "" "." $INSTDIR

    SectionSetFlags ${SecPtrace} 17

    !ifdef USE64
        SetRegView 64
    !endif

    ; We try HKCU first, then fall back to HKLM.
    ReadRegStr $0 HKCU Software\Python\PythonCore\2.7\InstallPath ""
    ${If} $0 == ""
        ReadRegStr $0 HKLM Software\Python\PythonCore\2.7\InstallPath ""
    ${EndIf}
    ${If} $0 == ""
        SectionSetFlags ${SecPython27} 16
    ${Else}
        StrCpy $Python27Packages "$0${PYTHON_PACKAGES}"
    ${EndIf}

    ; For HKCU we have no differentiator between 32 and 64-bit python 2.7
    ; We work around this by executing Python itself.
    ExecWait '"$0\python.exe" -c "import sys; exit(100 + (sys.maxsize > 2**32))"' $1
    ${If} $1 == ""
        SectionSetFlags ${SecPython27} 16
    ${Else}
    !ifdef USE64
        ${If} $1 == 100
            SectionSetFlags ${SecPython27} 16
        ${Endif}
    !else
        ${If} $1 == 101
            SectionSetFlags ${SecPython27} 16
        ${Endif}
    !endif
    ${EndIf}

    !ifdef USE64
    ReadRegStr $0 HKCU Software\Python\PythonCore\3.7\InstallPath ""
    ${If} $0 == ""
        ReadRegStr $0 HKLM Software\Python\PythonCore\3.7\InstallPath ""
    ${EndIf}
    !else
    ReadRegStr $0 HKCU Software\Python\PythonCore\3.7-32\InstallPath ""
    ${If} $0 == ""
        ReadRegStr $0 HKLM Software\Python\PythonCore\3.7-32\InstallPath ""
    ${EndIf}
    !endif

    ${If} $0 == ""
        SectionSetFlags ${SecPython37} 16
    ${Else}
        StrCpy $Python37Packages "$0${PYTHON_PACKAGES}"
    ${EndIf}

    SetShellVarContext all
FunctionEnd

function un.onInit
    !ifdef USE64
        SetRegView 64
    !endif
    SetShellVarContext all
FunctionEnd

Section "Uninstall"
    MessageBox MB_YESNO "Are you sure you want to uninstall ${PRODUCT_NAME}?" IDNO NoUn

    ReadRegStr $INSTDIR          HKLM "Software\${PRODUCT_PUBLISHER}\${PRODUCT_NAME}" "InstallLocation"
    ReadRegStr $Python27Packages HKLM "Software\${PRODUCT_PUBLISHER}\${PRODUCT_NAME}" "Python27Location"
    ReadRegStr $Python37Packages HKLM "Software\${PRODUCT_PUBLISHER}\${PRODUCT_NAME}" "Python37Location"

    Delete "$INSTDIR\core.py"
    Delete "$INSTDIR\events.py"
    Delete "$INSTDIR\heaptrace.py"
    Delete "$INSTDIR\inject.py"
    Delete "$INSTDIR\keylogger.py"
    Delete "$INSTDIR\module_exports.py"
    Delete "$INSTDIR\modules.py"
    Delete "$INSTDIR\processes.py"
    Delete "$INSTDIR\registers.py"
    Delete "$INSTDIR\regtrace.py"
    Delete "$INSTDIR\remote_break.py"
    Delete "$INSTDIR\remote_thread.py"
    Delete "$INSTDIR\AUTHORS"
    Delete "$INSTDIR\ChangeLog"
    Delete "$INSTDIR\COPYING"
    Delete "$INSTDIR\COPYING.LESSER"
    Delete "$INSTDIR\README.md"
    Delete "$INSTDIR\uninstall.exe"
    RMDir  "$INSTDIR"
    ; XXX: When a user changes paths this is a little quirky.  However, it'll
    ; only remove empty directories, so it's not the end of the world.
    RMDir  "$INSTDIR\.."

    ${If} $Python27Packages != ""
        Delete "$Python27Packages\_ptrace.pyd"
    ${Endif}

    ${If} $Python37Packages != ""
        Delete "$Python37Packages\_ptrace.pyd"
    ${Endif}

    !insertmacro UninstallLib DLL NOTSHARED REBOOT_NOTPROTECTED $SYSDIR\libptrace.dll

    ; Delete start menu entries.
    !insertmacro MUI_STARTMENU_GETFOLDER Application $StartMenuFolder
    Delete "$SMPROGRAMS\$StartMenuFolder\libptrace.lnk"
    Delete "$SMPROGRAMS\$StartMenuFolder\Uninstall.lnk"
    RMDir  "$SMPROGRAMS\$StartMenuFolder\"
    RMDir  "$SMPROGRAMS\${PRODUCT_PUBLISHER}\"

    ; Delete the registry keys.
    DeleteRegKey HKLM "Software\${PRODUCT_PUBLISHER}\${PRODUCT_NAME}"
    DeleteRegKey /ifempty HKLM "Software\${PRODUCT_PUBLISHER}"

NoUn:
    Quit
SectionEnd

; Component page descriptions.
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
!insertmacro MUI_DESCRIPTION_TEXT ${SecPtrace}   $(DESC_SecPtrace)
!insertmacro MUI_DESCRIPTION_TEXT ${SecPython27} $(DESC_SecPython27)
!insertmacro MUI_DESCRIPTION_TEXT ${SecPython37} $(DESC_SecPython37)
!insertmacro MUI_FUNCTION_DESCRIPTION_END
