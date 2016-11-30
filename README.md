# ObRegisterCallBacksByPass
Modify process handle permissions
# Supports Win7x64 and win10x64 Only 
# How to use
Vs2015 + wdk10 compilation
If you use compile RestoreAccessExWin7x64 on Windows 7
If used on win10 compile RestoreAccess
RestoreApp responsible for driving load and communication
RestorePid is Pid has opened the handle process
GamePid process Pid is protected by CallBacks
# Example:
Start the CE, select a protected open process.
At this point if the search memory usually errors or search less than
RestoreApp operation at this time, 
after the success of the loaded driver, 
CE process pid RestorePid input, protected process pid GamePid input, 
click Restore, if prompt is successful, click again on the CE search the memory, will find can normal work
