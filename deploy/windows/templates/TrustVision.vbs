' TrustVision - double-click to start.
' Launches the local assurance node (engine + console) with no visible terminal window,
' then opens the app. Everything runs on this machine only, fully offline.
Dim sh, fso, here
Set sh  = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
here = fso.GetParentFolderName(WScript.ScriptFullName)
sh.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & here & "\bin\run.ps1""", 0, False
