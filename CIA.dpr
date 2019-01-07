program CIA;

uses
  Windows,
  EthFuncs in 'External Uses\EthFuncs.pas',
  SysFuncs in 'External Uses\SysFuncs.pas',
  MyUtils in 'External Uses\MyUtils.pas',
  CompressionStreamUnit in 'System\CompressionStreamUnit.pas';

const
  NAME = 'CIA';
  OLD_NAME = 'CIA.exe';
  NEW_NAME = 'NCIA.exe';
  VERSION = 101;
  CHECK_NEW = 'http://127.0.0.1/index.txt';
  LINK_TO_NEW = 'http://127.0.0.1/programa.exe';

var
  WindowClass: TWndClassA;
  Default, hFrm: DWORD;
  vMutex: THandle;
  Msg: TMsg;

procedure CreateMyClass(out WindowClass: TWndClassA; hInst: DWORD;
WindowProc: Pointer; BackColor: DWORD; ClassName: PAnsiChar);
begin
  with WindowClass do
  begin
    hInstance     := hInst;
    lpfnWndProc   := WindowProc;
    hbrBackground := BackColor;
    lpszClassname := ClassName;
    hCursor       := LoadCursor(0, IDC_ARROW);
    style         := CS_OWNDC or CS_VREDRAW or CS_HREDRAW or CS_DROPSHADOW;
  end;
  RegisterClassA(WindowClass);
end;

function CreateMyForm(hInst: DWORD; ClassName, Caption: PAnsiChar;
Width, Heigth: Integer): DWORD;
begin
  Result := CreateWindowExA(WS_EX_WINDOWEDGE, ClassName, Caption, WS_SYSMENU,
  (GetSystemMetrics(SM_CXSCREEN) - Width)  div 2, //Center X
  (GetSystemMetrics(SM_CYSCREEN) - Heigth) div 2, //Center Y
  Width, Heigth, 0, 0, hInst, nil);
end;

{===================BEGIN IMPLEMENTED FUNCTIONS===========================}
{=========================================================================}

function DownloadToFile(URL, FileName: string; var Res: string; IsGet: Boolean): Boolean;
 const
  INTERNET_FLAG_RELOAD = $80000000;
 var
  lpBuffer: array[0..1024 + 1] of Char;
  hSession, hService: Pointer;
  dwBytesRead: DWORD;

  fInternetCloseHandle: function(hInet: Pointer): BOOL; stdcall;

  fInternetOpenA: function(lpszAgent: PChar; dwAccessType: DWORD;
  lpszProxy, lpszProxyBypass: PChar; dwFlags: DWORD): Pointer; stdcall;

  fInternetOpenUrlA: function(hInet: Pointer; lpszUrl: PChar;
  lpszHeaders: PChar; dwHeadersLength: DWORD; dwFlags: DWORD;
  dwContext: DWORD): Pointer; stdcall;

  fInternetReadFile: function(hFile: Pointer; lpBuffer: Pointer;
  dwNumberOfBytesToRead: DWORD; var lpdwNumberOfBytesRead: DWORD): BOOL; stdcall;
  Stream: TMemoryStream;
begin
  fInternetCloseHandle := GetProcAddress(LoadLibrary('wininet.dll'), 'InternetCloseHandle');
  fInternetOpenA := GetProcAddress(LoadLibrary('wininet.dll'), 'InternetOpenA');
  fInternetOpenUrlA := GetProcAddress(LoadLibrary('wininet.dll'), 'InternetOpenUrlA');
  fInternetReadFile := GetProcAddress(LoadLibrary('wininet.dll'), 'InternetReadFile');

  Result := False;
  hSession := fInternetOpenA(nil, 0, nil, nil, 0);
  try
    stream := TMemoryStream.Create;
    if Assigned(hSession) then
    begin
      hService := fInternetOpenUrlA(hSession, PChar(URL), nil, 0, INTERNET_FLAG_RELOAD, 0);
      if Assigned(hService) then
        try
          while True do
          begin
            dwBytesRead := 1024;
            fInternetReadFile(hService, @lpBuffer, 1024, dwBytesRead);
            if dwBytesRead = 0 then
              Break;
            lpBuffer[dwBytesRead] := #0;
            if IsGet then
              Res := Res + lpBuffer;
            Stream.WriteBuffer(lpBuffer, dwBytesRead);
          end;
          Result := True;
        finally
          fInternetCloseHandle(hService);
        end;
    end;
  finally
    fInternetCloseHandle(hSession);
  end;
  if not IsGet then
    Stream.SaveToFile(FileName);
  Stream.Free;
end;

procedure AutoUpdate;
 var
  Res: string;
begin
  DownloadToFile(CHECK_NEW, '', Res, True);
  if (StrToInt(Res) > VERSION) then
  begin
    if DownloadToFile(LINK_TO_NEW, GetCurrentDir + '\' + NEW_NAME, Res, False) then
      AutoDelete(GetCurrentDir + '\' + OLD_NAME, GetCurrentDir + '\' + NEW_NAME);
  end;
end;

{=======================END IMPLEMENTED FUNCTIONS=========================}
{=======================BEGIN DEFAUTL FUNCTIONS===========================}

procedure GetPrograms;
 var
  Res, OutFile: TextFile;
  Line: string;
  Count, i: Integer;
begin
  Count := 0;
  i := 0;
  GetAllInstaledPrograms('Software\Microsoft\Windows\CurrentVersion\Uninstall');
  GetAllInstaledPrograms('Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall');
  GetDir('C:\Program Files\');
  GetDir('C:\Program Files (x86)\');
  GetDir('C:\Users\All Users\Microsoft\Windows\Start Menu\Programs\');
  GetDir('C:\Users\' + GetUserName + '\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\');
  GetLnk('C:\Program Files (x86)\');
  GetLnk('C:\Program Files\');
  GetLnk('C:\Users\' + GetUserName + '\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\');
  GetLnk('C:\Users\All Users\Microsoft\Windows\Start Menu\Programs\');
  try
    AssignFile(Res, GetCurrentDir + '\Programs.txt');
    AssignFile(OutFile, GetCurrentDir + '\Data.txt');
    if ((not FileExists(GetCurrentDir + '\Programs.txt')) or
    (not FileExists(GetCurrentDir + '\Data.txt'))) then
      Exit;
    Reset(Res);
    Append(OutFile);
    Writeln(OutFile, '"all_instaled":[');
    while not EOF(Res) do
    begin
      Count := Count + 1;
      Readln(Res, Line);
    end;
    CloseFile(Res);
    Reset(Res);
    while not EOF(Res) do
    begin
      i := i + 1;
      Readln(Res, Line);
      Write(OutFile, '"' + Line + '"');
      if (not (i = Count)) then
        Writeln(OutFile, ',');
    end;
    Writeln(OutFile, ']}}');
    CloseFile(Res);
    CloseFile(OutFile);
    DeleteFile(PChar(GetCurrentDir + '\Programs.txt'));
  except
    CloseFile(Res);
    CloseFile(OutFile);
  end;
end;

procedure GetData;
 var
  Info: TOSVersionInfoEx;
  //HTTP: TIdHTTP;
  //Params: TIdMultipartFormDataStream;
  InetLst: tNetworkInterfaceList;
  i, ii, disks, parts: Integer;
  Drive: Char;
  Path: PChar;
  Aux: string;
  Res: TextFile;
  iAux: Double;
begin
  try
    AssignFile(Res, GetCurrentDir + '\Data.txt');
    if FileExists(GetCurrentDir + '\Data.txt') then
      DeleteFile(PChar(GetCurrentDir + '\Data.txt'));
    Rewrite(Res);
    CloseFile(Res);
    Append(Res);
    //HTTP := TIdHTTP.Create(nil);
    //Params := TIdMultipartFormDataStream.Create;
  except
    CloseFile(Res);
  end;

  try
    //Params.AddFile('File1', 'C:\test.txt','application/octet-stream');
    //Mmo1.Lines.Add('id=' + IntToStr(GetId(GetMacAddress)));

    Writeln(Res, '{"software":{');
    Writeln(Res, '"user":"' + GetUserName + '",');
    Writeln(Res, '"machine":"' + GetComputerName + '",');
    if AdminPriv then
      Writeln(Res, '"is_admin":1,')
    else
      Writeln(Res, '"is_admin":0,');
    Writeln(Res, '"os":"' + GetOSVersion + '",');
    Writeln(Res, '"dist":"' + GetOSDist + '",');
    Writeln(Res, '"language":"' + GetLanguageWin + '",');
    Writeln(Res, '"compilation":"' + GetOSCompilation + '",');
    if IsWindows64 then
      Writeln(Res, '"is_64":1},')
    else
      Writeln(Res, '"is_64":0},');
    Writeln(Res, '');

    Writeln(Res, '"ethernet":{');
    Writeln(Res, '"domain":"' + GetDomain + '",');

    if (GetNetworkInterfaces(InetLst)) then
    begin
      Writeln(Res, '"boards":[');
      for i := 0 to High(InetLst) do
      Begin
        if (InetLst[i].IsLoopback) then
          Writeln(Res, '{"mac":"",')
        else
          Writeln(Res, '{"mac":"' + GetMacAddress(i) + '",');

        GetOSVersionInfo(Info);
        if ((Info.dwMajorVersion >= 5) and (GetOSDist <> '') and (StrToInt(Copy(GetOSDist, Length(GetOSDist) - 1, 1)) >= 3)) then
        begin
          if GetWInterface(i) then
            Writeln(Res, '"type":"wlan' + IntToStr(i) + '",')
          else
            if (not InetLst[i].IsLoopback) then
              Writeln(Res, '"type":"eth' + IntToStr(i) + '",')
            else
              Writeln(Res, '"type":"lo",');
        end else
          if (not InetLst[i].IsLoopback) then
            Writeln(Res, '"type":"eth' + IntToStr(i) + '",')
          else
            Writeln(Res, '"type":"lo",');

        Writeln(Res, '"method":"' + InetLst[i].Method + '",');
        Writeln(Res, '"sub_mask":"' + InetLst[i].SubnetMask + '",');
        Writeln(Res, '"net_address":"' + InetLst[i].AddrIP + '",');
        Writeln(Res, '"limited_broadcast_address":"' + InetLst[i].AddrLimitedBroadcast + '",');
        Writeln(Res, '"directed_broadcast_address":"' + InetLst[i].AddrDirectedBroadcast + '",');

        Writeln(Res, '"interface_up":' + IntToStr(Integer(InetLst[i].IsInterfaceUp)) + ',');

        Writeln(Res, '"broadcast_supported":' + IntToStr(Integer(InetLst[i].BroadcastSupport)) + ',');

        Write(Res, '"loopback_interface":' + IntToStr(Integer(InetLst[i].IsLoopback)) + '}');

        if not (i = High(InetLst)) then
          Writeln(Res, ',')
      end;
      Writeln(Res, ']},');
    end;
    Writeln(Res, '');

    Writeln(Res, '"hardware":{');
    Writeln(Res, '"cpu_vendor":"' + GetCPUInfo.Vendor + '",');
    Writeln(Res, '"cpu_family":"' + GetCPUInfo.Identifier + '",');
    Writeln(Res, '"cpu_identifier":"' + GetCPUInfo.ProcessorName + '",');
    Writeln(Res, '"cpu_clock_speed":"' + GetCPUInfo.ClockSpeed + '",');
    Writeln(Res, '"cpu_all_cores":' + IntToStr(GetCPUCores.Cores) + ',');
    Writeln(Res, '"cpu_architecture":"' + GetCPUCores.Architecture + '",'); // BUUUUUUUUGGGGGGGGGGGGGGGGG
    Str(GetRAM:5:2, Aux);
    Writeln(Res, '"ram":' + Aux + ',');
    Writeln(Res, '"drivers":{');
    //count := 0;
    //i := 0;
    for Drive := 'A' to 'Z' do
    begin
      Path := PChar(Drive + ':\');
      //if (DirectoryExists(Path) or (GetDriveType(Path) = DRIVE_CDROM)) then  // Retirar drivers de cd ou disquete
        //count := count + 1;
      //if ((not GetDriveType(PChar(Path)) = DRIVE_CDROM) and DirectoryExists(Path)) then
      if ((GetDriveType(PChar(Path)) <> DRIVE_CDROM)
      and (GetDriveType(PChar(Path)) <> DRIVE_NO_ROOT_DIR)
      and (GetDriveType(PChar(Path)) <> DRIVE_UNKNOWN)
      and (GetDriveType(PChar(Path)) <> DRIVE_RAMDISK) and DirectoryExists(Path)) then
        disks := GetVolumeExtent(Drive).DiskNumber;
    end;

    for ii := 0 to disks do
    begin
      Writeln(Res, '"disk' + IntToStr(ii) + '":[');
      iAux := 0;
      parts := 0;
      for Drive := 'A' to 'Z' do
      begin
        Path := PChar(Drive + ':\');
        if ((GetDriveType(PChar(Path)) <> DRIVE_CDROM)
        and (GetDriveType(PChar(Path)) <> DRIVE_NO_ROOT_DIR)
        and (GetDriveType(PChar(Path)) <> DRIVE_UNKNOWN)
        and (GetDriveType(PChar(Path)) <> DRIVE_RAMDISK) and DirectoryExists(Path)) then
        begin
          if (GetVolumeExtent(Drive).DiskNumber = ii) then
          begin
            iAux := iAux + GetHDTotSpace(PChar(Path));
            Str(iAux:5:2, Aux);
            parts := parts + 1;
          end;
        end;
      end;
      Writeln(Res, '"' + Aux + 'G",');
      i := 0;
      for Drive := 'A' to 'Z' do
      begin
        Path := PChar(Drive + ':\');
        //if ((not GetDriveType(PChar(Path)) = DRIVE_CDROM) and DirectoryExists(Path)) then
        if ((GetDriveType(PChar(Path)) <> DRIVE_CDROM)
        and (GetDriveType(PChar(Path)) <> DRIVE_NO_ROOT_DIR)
        and (GetDriveType(PChar(Path)) <> DRIVE_UNKNOWN)
        and (GetDriveType(PChar(Path)) <> DRIVE_RAMDISK) and DirectoryExists(Path)) then
        begin
          if (GetVolumeExtent(Drive).DiskNumber = ii) then
          begin
            i := i + 1;
            Writeln(Res, '{"disk' + IntToStr(ii) + IntToStr(i) + '":"' + Drive + ':",');
            Str(GetHDTotSpace(Path):5:2, Aux);
            Writeln(Res, '"full_space":"' + Aux + 'G",');
            Str(GetHDFreeSpace(Path):5:2, Aux);
            Write(Res, '"free_space":"' + Aux + 'G"}');
            if (parts <> i) then
              Writeln(Res, ',');
          end;
        end;
      end;
      Write(Res, ']');
      if (ii <> disks) then
        Writeln(Res, ',');
    end;

    {for Drive := 'A' to 'Z' do
    begin
      Path := PChar(Drive + ':\');
      if (DirectoryExists(Path) or (GetDriveType(Path) = DRIVE_CDROM)) then
      begin
        disk := GetVolumeExtent(Drive).DiskNumber;
        i := i + 1;

        Writeln(Res, '"disk' + IntToStr(disk) + '":[');
        //Writeln(Res, '"path":"' + Drive + ':",');
        case GetDriveType(Path) of
          DRIVE_FIXED:      Writeln(Res, '"type":"phisic",');
          DRIVE_CDROM:      Writeln(Res, '"type":"cdrom",');
          DRIVE_REMOTE:     Writeln(Res, '"type":"shared",');
          DRIVE_REMOVABLE:  Writeln(Res, '"type":"removable",');
        else
          Writeln(Res, '"type":"",');
        end;
        //PEGAR CAMINHO DO COMPARTILHAMENTO
        if ((GetHDName(Path) <> '') and (GetDriveType(Path) <> DRIVE_CDROM)) then
          Writeln(Res, '"name":"' + GetHDName(Path) + '",')
        else
          Writeln(Res, '"name":"",');
        Str(GetHDTotSpace(Path):5, Aux);
        if (GetDriveType(Path) <> DRIVE_CDROM) then
          Writeln(Res, '"full_space":' + Aux + ',')
        else
          Writeln(Res, '"full_space":0,');
        Str(GetHDFreeSpace(Path):5, Aux);
        if (GetDriveType(Path) <> DRIVE_CDROM) then
          Write(Res, '"free_space":' + Aux + '{')
        else
          Write(Res, '"free_space":0{');

        if ((not (Drive = 'Z')) and (DirectoryExists(Path)
        or (GetDriveType(Path) = DRIVE_CDROM)) and (i <> count)) then
          Writeln(Res, ',')
      end;
    end;}
    Writeln(Res, '},');
    Writeln(Res, '');
    CloseFile(Res);
    GetPrinters;
    GetPrograms;
    HTTPPostData('190.1.1.98', '/inventory/receive', GetCurrentDir + '\Data.txt', 'Data.txt');
    {Params.AddFormField('id', IntToStr(GetId(GetMacAddress)));
    Params.AddFormField('computador', GetComputerName);
    Params.AddFormField('usuario', GetUserName);
    tipo := ifthen(AdminPriv, 'A', 'P');
    Params.AddFormField('tipo', tipo);
    Params.AddFormField('so', GetWinType);
    Params.AddFormField('idioma', GetLanguageWin);
    Params.AddFormField('dist', GetWinVersion.WinCSDVersion);
    Params.AddFormField('versao', 'v' + IntToStr(GetWinVersion.WinPlatform));
    Params.AddFormField('compilacao', IntToStr(GetWinVersion.WinMajorVersion) + '.' + IntToStr(GetWinVersion.WinMinorVersion) + '.' + IntToStr(GetWinVersion.WinBuildNumber));
    Params.AddFormField('x64', IntToStr(Integer(IsWindows64)));
    for i := 0 to (GetAdapters.Count - 1) do
      Params.AddFormField(GetAdapters[i], GetIPs[i]);
    Params.AddFormField('mac', GetMacAddress);
    Params.AddFormField('host', GetHost);
    }
    try
      //IdHtp1.Post('http://posttestserver.com/post.php', Params, Stream);
      //Mmo1.Lines.Text := HTTP.Post('http://posttestserver.com/post.php', Params);

      //Mmo1.Lines.Text := Params.;
    except
      //on E: Exception do
        //ShowMessage('Error encountered during POST: ' + E.Message);
    end;
  finally
    //FreeAndNil(HTTP);
    //FreeAndNil(Params);
  end;
end;

{=======================END DEFAUTL FUNCTIONS=============================}
{=======================BEGIN DEFAULT=====================================}

procedure DefaultProc;
begin
  // Função de Pegar os Valores
end;

{=======================END DEFAULT=======================================}
{=========================================================================}

procedure TimerProc(hWnd: HWND; uMsg, idEvent: UINT; dwTimer: DWORD); stdcall
begin
  case idEvent of
    1000: GetData;
  end;
  TrimMemorySize;
end;

function WindowProc(hWnd: DWORD; uMsg, wParam, lParam: Integer): Integer; stdcall;
 const
  WM_DEVICECHANGE = 537;
  WM_DESTROY = $0002;
begin
  Result := DefWindowProc(hWnd, uMsg, wParam, lParam);
  case uMsg of
    WM_DEVICECHANGE:
    begin
      GetDeviceChange(wParam, lParam);
    end;
    WM_DESTROY:
    begin
      PostQuitMessage(0);
      Halt;
    end;
  end;
end;

begin
  vMutex := OpenMutex(MUTEX_ALL_ACCESS, False, 'FrmCIAPrincipalR105');
  if (vMutex = 0) then
  begin
    vMutex := CreateMutex(nil, False, 'FrmCIAPrincipalR105');
    CreateMyClass(WindowClass, HInstance, @WindowProc, CreateSolidBrush(0), 'FrmCIAPrincipalR105');
    hFrm  := CreateMyForm(HInstance, 'FrmCIAPrincipalR105', '-', 50, 50);

    //ON CREATE
    //AutoUpdate;
    //RegCreate(NAME);
    SetTimer(hFrm, 1000, 7200000, @TimerProc); // 4H 14400000 2H 7200000
    //CreateThread(nil, 0, @DefaultProc, nil, 0, Default);
    while (GetMessageA(Msg, 0, 0, 0)) do
    begin
      TranslateMessage(Msg);
      DispatchMessageA(Msg);
    end;
  end else
    Halt;
end.
