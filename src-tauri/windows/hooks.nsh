!macro NSIS_HOOK_POSTINSTALL
  CopyFiles /SILENT "$INSTDIR\resources\WinDivert.dll" "$INSTDIR\WinDivert.dll"
  CopyFiles /SILENT "$INSTDIR\resources\WinDivert64.sys" "$INSTDIR\WinDivert64.sys"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  Delete "$INSTDIR\WinDivert.dll"
  Delete "$INSTDIR\WinDivert64.sys"
!macroend
