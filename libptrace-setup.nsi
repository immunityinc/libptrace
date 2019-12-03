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
!define MUI_STARTMENUPAGE_REGISTRY_VALUENAME "Start Menu Folder"

Name    "libptrace"
!ifdef USE64
    outfile "libptrace-setup64.exe"
!else
    outfile "libptrace-setup32.exe"
!endif
RequestExecutionLevel admin

; Variables.
Var StartMenuFolder
Var PythonPackages

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

!ifdef USE64
    InstallDir "$PROGRAMFILES64\${PRODUCT_PUBLISHER}\${PRODUCT_NAME}"
!else
    InstallDir "$PROGRAMFILES\${PRODUCT_PUBLISHER}\${PRODUCT_NAME}"
!endif

InstallDirRegKey HKLM "Software\${PRODUCT_PUBLISHER}\${PRODUCT_NAME}" ""

function .onInit
    !ifdef USE64
        SetRegView 64
    !endif

    ReadRegStr $0 HKLM Software\Python\PythonCore\2.7\InstallPath ""

    ${If} $0 == ""
        MessageBox MB_OK|MB_ICONSTOP "Python 2.7 was not found on the system: $0"
        Quit
    ${EndIf}

    StrCpy $PythonPackages "$0${PYTHON_PACKAGES}"
    SetShellVarContext all
FunctionEnd

; Files to install
Section "libptrace" SecPtrace
    SetOverwrite try

    CreateDirectory $PythonPackages
    SetOutPath $PythonPackages
    File "/oname=_ptrace.pyd" "python/libpyptrace.dll"
    !insertmacro InstallLib DLL NOTSHARED REBOOT_NOTPROTECTED src/libptrace.dll $SYSDIR\libptrace.dll $SYSDIR

    SetOutPath $INSTDIR
    File "python/scripts/*.py"
    File "AUTHORS"
    File "ChangeLog"
    File "COPYING"
    File "COPYING.LESSER"
    File "README.md"

    ; Store installation directory.
    WriteRegStr HKLM "Software\${PRODUCT_PUBLISHER}\${PRODUCT_NAME}" "" $INSTDIR

    ; Uninstaller creation.
    SetOutPath $INSTDIR
    WriteUninstaller "$INSTDIR\uninstall.exe"

    !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
        CreateDirectory "$SMPROGRAMS\$StartMenuFolder\"
        CreateShortCut "$SMPROGRAMS\$StartMenuFolder\uninstall.lnk" "$INSTDIR\uninstall.exe"
    !insertmacro MUI_STARTMENU_WRITE_END
SectionEnd

function un.onInit
    !ifdef USE64
        SetRegView 64
    !endif

    ReadRegStr $0 HKLM Software\Python\PythonCore\2.7\InstallPath ""

    ${If} $0 == ""
        MessageBox MB_OK|MB_ICONSTOP "Python 2.7 was not found on the system: $0"
        Quit
    ${EndIf}

    StrCpy $PythonPackages "$0${PYTHON_PACKAGES}"
    SetShellVarContext all
FunctionEnd

Section "Uninstall"
    MessageBox MB_YESNO "Are you sure you want to uninstall ${PRODUCT_NAME}?" IDNO NoUn

    ; Shortcuts are present in the All Users folder.
    SetShellVarContext all

    ; Delete all the installed files.
    ; XXX: this will not check weird installation directories.
    RMDir /r $INSTDIR
!ifdef USE64
    RMDir "$PROGRAMFILES64\${PRODUCT_PUBLISHER}"
!else
    RMDir "$PROGRAMFILES\${PRODUCT_PUBLISHER}"
!endif

    ; Delete the .pyd module.
    Delete "$PythonPackages\_ptrace.pyd"

    ; Delete the installed library.
    !insertmacro UninstallLib DLL NOTSHARED REBOOT_NOTPROTECTED $SYSDIR\libptrace.dll

    ; Delete start menu entries.
    !insertmacro MUI_STARTMENU_GETFOLDER Application $StartMenuFolder
    Delete "$SMPROGRAMS\$StartMenuFolder\libptrace.lnk"
    Delete "$SMPROGRAMS\$StartMenuFolder\Uninstall.lnk"
    RMDir "$SMPROGRAMS\$StartMenuFolder\"
    RMDir "$SMPROGRAMS\${PRODUCT_PUBLISHER}\"

    ; Delete the registry keys.
    DeleteRegKey HKLM "Software\${PRODUCT_PUBLISHER}\${PRODUCT_NAME}"
    DeleteRegKey /ifempty HKLM "Software\${PRODUCT_PUBLISHER}"

NoUn:
    Quit
SectionEnd

; Component page descriptions.
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
!insertmacro MUI_DESCRIPTION_TEXT ${SecPtrace}  $(DESC_SecPtrace)
!insertmacro MUI_FUNCTION_DESCRIPTION_END
