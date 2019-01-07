unit MyUtils;

interface

uses Windows, TLhElp32;

function GetProcessIDByName(ProcessName: string): DWORD;
function WriteStringToProcess(hProcess: Cardinal; S: string): Pointer;
function WriteDataToProcess(hProcess, dwSize: Cardinal; RemoteWriteData: Pointer): Pointer;
function ProcessExists(ExeFileName: string): Boolean;
function UpperCase(const S: string): string;
function LowerCase(const S: string): string;
function Trim(const S: string): string;
function IntToHex(Value: LongInt; Digits: Integer): string;
function IntToStr(Value: Integer): ShortString;
function StrToInt(Value: ShortString): Integer;
function StrLen(const Str: PChar): Cardinal;
function StrPas(const Str: PChar): string;
function AnsiSameText(const S1, S2: string): Boolean;
function DirectoryExists(const Name: string): Boolean;
function FileExists(FileName: string): Boolean;
function ExtractFileName(const FileName: string): string;
function GetCurrentDir: string;
function AllocMem(Size: Cardinal): Pointer;

implementation

function GetProcessIDByName(ProcessName: string): DWORD;
 var
  MyHandle: THandle;
  Struct: TProcessEntry32;
begin
  Result := 0;
  ProcessName := LowerCase(ProcessName);
  try
    MyHandle := CreateToolHelp32SnapShot(TH32CS_SNAPPROCESS, 0);
    Struct.dwSize := Sizeof(TProcessEntry32);
    if Process32First(MyHandle, Struct) then
    if ProcessName = LowerCase(Struct.szExeFile) then
    begin
      Result := Struct.th32ProcessID;
      Exit;
    end;
    while Process32Next(MyHandle, Struct) do
    if ProcessName = LowerCase(Struct.szExeFile) then
    begin
      Result := Struct.th32ProcessID;
      Exit;
    end;
  except
    Exit;
  end;
end;

function WriteStringToProcess(hProcess: Cardinal; S: string): Pointer;
 var
  BytesWritten: Cardinal;
begin
  Result := VirtualAllocEx(hProcess, nil, Length(S) + 1, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  WriteProcessMemory(hProcess, Result, PChar(S), Length(S) + 1, BytesWritten);
end;

function WriteDataToProcess(hProcess, dwSize: Cardinal; RemoteWriteData: Pointer): Pointer;
 var
  BytesWritten: Cardinal;
begin
  Result := VirtualAllocEx(hProcess, nil, dwSize, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  WriteProcessMemory(hProcess, Result, RemoteWriteData, dwSize, BytesWritten);
end;

function ProcessExists(ExeFileName: string): Boolean;
 const
  PROCESS_TERMINATE = $0001;
 var
  Loop: BOOL;
  FSnapshotHandle: THandle;
  FProcessEntry32: TProcessEntry32;
begin
  Result := False;
  FSnapshotHandle := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  FProcessEntry32.dwSize := Sizeof(FProcessEntry32);
  Loop := Process32First(FSnapshotHandle,FProcessEntry32);
  while Integer(Loop) <> 0 do
  begin
    if ((UpperCase(ExtractFileName(
    FProcessEntry32.szExeFile)) = UpperCase(ExeFileName))
    or (UpperCase(FProcessEntry32.szExeFile) = UpperCase(ExeFileName))) then
    begin
      Result := True;
      Exit;
    end;
    Loop := Process32Next(FSnapshotHandle,FProcessEntry32);
  end;
  CloseHandle(FSnapshotHandle);
end;

function UpperCase(const S: string): string;
 var
  I: Integer;
begin
  Result := S;
  for I := 1 to Length(S) do
    if Result[I] in ['a'..'z'] then
       Dec(Result[I], 32);
end;

function LowerCase(const S: string): string;
 var
  Ch: Char;
  L: Integer;
  Source, Dest: PChar;
begin
  L := Length(S);
  SetLength(Result, L);
  Source := Pointer(S);
  Dest := Pointer(Result);
  while (L <> 0) do
  begin
    Ch := Source^;
    if (Ch >= 'A') and (Ch <= 'Z') then
      Inc(Ch, 32);
    Dest^ := Ch;
    Inc(Source);
    Inc(Dest);
    Dec(L);
  end;
end;

function Trim(const S: string): string;
 var
  I, L: Integer;
begin
  L := Length(S);
  I := 1;
  while (I <= L) and (S[I] <= ' ') do Inc(I);
  if I > L then Result := '' else
  begin
    while S[L] <= ' ' do Dec(L);
    Result := Copy(S, I, L - I + 1);
  end;
end;

function IntToHex(Value: LongInt; Digits: Integer): string;
 var
  Res: string;
begin
  if (Value = 0) then
    Res := StringOfChar('0', Digits);
  if (Value < 0) then
    Res := StringOfChar('F', 16);

  while (Value > 0) do
  begin
    case (Value mod 16) of
      10: Res := 'A' + Res;
      11: Res := 'B' + Res;
      12: Res := 'C' + Res;
      13: Res := 'D' + Res;
      14: Res := 'E' + Res;
      15: Res := 'F' + Res;
    else
      Res := IntToStr(Value mod 16) + Res;
    end;
    Value := Value div 16;
  end;
  if ((Digits > 1) and (Length(Res) < Digits)) then
  begin
    Res := StringOfChar('0', (Digits - Length(Res))) + Res;
  end;
  Result := Res;
end;

function IntToStr(Value: Integer): ShortString;
// Value  = eax
// Result = edx
asm
  push ebx
  push esi
  push edi

  mov edi,edx
  xor ecx,ecx
  mov ebx,10
  xor edx,edx

  cmp eax,0 // check for negative
  setl dl
  mov esi,edx
  jnl @reads
  neg eax

  @reads:
    mov  edx,0   // edx = eax mod 10
    div  ebx     // eax = eax div 10
    add  edx,48  // '0' = #48
    push edx
    inc  ecx
    cmp  eax,0
  jne @reads

  dec esi
  jnz @positive
  push 45 // '-' = #45
  inc ecx

  @positive:
  mov [edi],cl // set length byte
  inc edi

  @writes:
    pop eax
    mov [edi],al
    inc edi
    dec ecx
  jnz @writes

  pop edi
  pop esi
  pop ebx
end;

function StrToInt(Value: ShortString): Integer;
// Value   = eax
// Result  = eax
asm
  push ebx
  push esi

  mov esi,eax
  xor eax,eax
  movzx ecx,Byte([esi]) // read length byte
  cmp ecx,0
  je @exit

  movzx ebx,Byte([esi+1])
  xor edx,edx // edx = 0
  cmp ebx,45  // check for negative '-' = #45
  jne @loop

  dec edx // edx = -1
  inc esi // skip '-'
  dec ecx

  @loop:
    inc   esi
    movzx ebx,Byte([esi])
    imul  eax,10
    sub   ebx,48 // '0' = #48
    add   eax,ebx
    dec   ecx
  jnz @loop

  mov ecx,eax
  and ecx,edx
  shl ecx,1
  sub eax,ecx

  @exit:
  pop esi
  pop ebx
end;

function StrLen(const Str: PChar): Cardinal; assembler;
asm
        MOV     EDX,EDI
        MOV     EDI,EAX
        MOV     ECX,0FFFFFFFFH
        XOR     AL,AL
        REPNE   SCASB
        MOV     EAX,0FFFFFFFEH
        SUB     EAX,ECX
        MOV     EDI,EDX
end;

function StrPas(const Str: PChar): string;
begin
  Result := Str;
end;

function AnsiCompareText(const S1, S2: string): Integer;
begin
  Result := CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE, PChar(S1), Length(S1), PChar(S2), Length(S2)) - 2;
end;

function AnsiSameText(const S1, S2: string): Boolean;
begin
  Result := AnsiCompareText(S1, S2) = 0;
end;

function DirectoryExists(const Name: string): Boolean;
 var
  Code: Integer;
begin
  Code := GetFileAttributes(PChar(Name));
  Result := (Code <> -1) and (FILE_ATTRIBUTE_DIRECTORY and Code <> 0);
end;

function FileExists(FileName: string): Boolean;
 var
  FndData: TWin32FindData;
  fndHandle: Integer;
  ErrorMode: Word;
begin
  Result := False;
  ErrorMode := SetErrorMode(SEM_FailCriticalErrors);
  fndHandle := FindFirstFile(PChar(FileName), FndData);
  SetErrorMode(ErrorMode);
  if fndHandle <> Integer( INVALID_HANDLE_VALUE ) then
  begin
    Windows.FindClose(fndHandle);
    if (FndData.dwFileAttributes and FILE_ATTRIBUTE_DIRECTORY) = 0 then
       Result := True;
  end;
end;

function StrScan(const Str: PChar; Chr: Char): PChar; assembler;
asm
        PUSH    EDI
        PUSH    EAX
        MOV     EDI,Str
        MOV     ECX,0FFFFFFFFH
        XOR     AL,AL
        REPNE   SCASB
        NOT     ECX
        POP     EDI
        MOV     AL,Chr
        REPNE   SCASB
        MOV     EAX,0
        JNE     @@1
        MOV     EAX,EDI
        DEC     EAX
@@1:    POP     EDI
end;

function LastDelimiter(const Delimiters, S: string): Integer;
 var
  P: PChar;
begin
  Result := Length(S);
  P := PChar(Delimiters);
  while Result > 0 do
  begin
    if (S[Result] <> #0) and (StrScan(P, S[Result]) <> nil) then
        Exit;
    Dec(Result);
  end;
end;

function ExtractFileName(const FileName: string): string;
 const
  PathDelim  = {$IFDEF MSWINDOWS} '\'; {$ELSE} '/'; {$ENDIF}
  DriveDelim = {$IFDEF MSWINDOWS} ':'; {$ELSE} '';  {$ENDIF}
  PathSep    = {$IFDEF MSWINDOWS} ';'; {$ELSE} ':'; {$ENDIF}
 var
  I: Integer;
begin
  I := LastDelimiter(PathDelim + DriveDelim, FileName);
  Result := Copy(FileName, I + 1, MaxInt);
end;

function GetCurrentDir: string;
begin
  GetDir(0, Result);
end;

function AllocMem(Size: Cardinal): Pointer;
begin
  GetMem(Result, Size);
  FillChar(Result^, Size, 0);
end;

end.