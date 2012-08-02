// DLLMasher.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

char* lookupRVA(char* dllData, PIMAGE_NT_HEADERS old_header, DWORD va, size_t* section = NULL, bool dontCareIfPadded = false)
{
  size_t optHdrSize = old_header->FileHeader.SizeOfOptionalHeader;
  PIMAGE_SECTION_HEADER seHdr = (PIMAGE_SECTION_HEADER)(((char*)&old_header->OptionalHeader) + optHdrSize);
  for (DWORD se = 0; se < old_header->FileHeader.NumberOfSections; se++)
  {
    IMAGE_SECTION_HEADER& h = seHdr[se];
    if (h.PointerToRawData)
    {
      if (va >= h.VirtualAddress && va < (h.VirtualAddress + (dontCareIfPadded ? h.Misc.VirtualSize : h.SizeOfRawData)))
      {
        if (section)
          *section = se;
        return dllData + h.PointerToRawData + (va - h.VirtualAddress);
      }
    }
  }
  if (section)
    *section = ~0U;
  return NULL;
}

struct Import
{
  std::string symbolName;
  std::string exportName;
  int exportOrdinal;
};

#pragma pack(1)
struct ARArchiveItemHeader
{
  char Name[16];
  char Date[12];
  char User[6];
  char Group[6];
  char Mode[8];
  char Size[10];
  char End[2];
};

#pragma pack(1)
struct DLLImportPseudoCOFFObject
{
  WORD Sig1;
  WORD Sig2;
  WORD Version;
  WORD Machine;
  DWORD TimeDateStamp;
  DWORD SizeOfData;
  WORD Ordinal;
  WORD Flags;
};

int _tmain(int argc, _TCHAR* argv[])
{
  if (argc != 2)
  {
    std::cerr << argv[0] << ": <dll to mash into a lib>" << std::endl << std::endl;
    return 1;
  }

  char inputFile[MAX_PATH];
  strcpy_s(inputFile, argv[1]);
  PathStripPath(inputFile);

  std::string nameNoPeriod = inputFile;
  std::replace(nameNoPeriod.begin(), nameNoPeriod.end(), '.', '_');


  std::ifstream is(argv[1], std::ios::binary);
  if (!is)
  {
    std::cerr << "Can't open " << argv[1] << std::endl;
    return 2;
  }

  is.seekg(0, std::ios::end);
  size_t sz = (size_t)is.tellg();
  is.seekg(0, std::ios::beg);

  std::vector<char> dllDataV(sz);
  char* dllData = dllDataV.data();
  is.read(dllData, sz);
  is.close();

  char* dllDataEnd = dllData + sz;

  PIMAGE_DOS_HEADER dllDOSHeader;
  PIMAGE_NT_HEADERS dllPEHeader;

  dllDOSHeader = (PIMAGE_DOS_HEADER)dllData;
  if (dllDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
    return 1;
  }

  dllPEHeader = (PIMAGE_NT_HEADERS)&dllData[dllDOSHeader->e_lfanew];
  if (dllPEHeader->Signature != IMAGE_NT_SIGNATURE) {
    return 1;
  }

  std::string intermeddiateImportLib = nameNoPeriod + "_Temp_Mashed_imports.lib";
  std::string intermeddiateObj = nameNoPeriod + "_Temp_Mashed.obj";


  std::ofstream os(intermeddiateObj.c_str(), std::ios::binary | std::ios::out);

  //write COFF header minus IMAGE_NT_SIGNATURE
  IMAGE_FILE_HEADER coffFileHeader = dllPEHeader->FileHeader;
  coffFileHeader.SizeOfOptionalHeader = 0; //nuke it
  coffFileHeader.PointerToSymbolTable = 0;
  coffFileHeader.NumberOfSymbols = 0;
  coffFileHeader.Characteristics = 0;
  os.write((char*)&coffFileHeader, sizeof(coffFileHeader));

  PIMAGE_SECTION_HEADER dllSectionHeaders = (PIMAGE_SECTION_HEADER)(((char*)&dllPEHeader->OptionalHeader) + dllPEHeader->FileHeader.SizeOfOptionalHeader);

  auto coffSectionHeaderFileOffset = os.tellp();
  std::vector<std::pair<DWORD,DWORD>> dllToCoffSectionVAShifts;
  std::vector<IMAGE_SECTION_HEADER> coffSectionHeaders;
  size_t textSection = 0;
  for (DWORD se = 0; se < dllPEHeader->FileHeader.NumberOfSections; se++)
  {
    coffSectionHeaders.push_back(dllSectionHeaders[se]);
    for (size_t b = 0; b < sizeof(IMAGE_SECTION_HEADER); b++)
      os.put((char)0xFF); //padd with garbage for now

    if (strcmp((const char*)coffSectionHeaders[se].Name, ".text") == 0)
      textSection = se;
  }

  std::vector<char> coffSymbolStringTable;
  std::vector<IMAGE_SYMBOL> coffSymbols;

  const std::string importedSymbolPrefix("__imp_");

  PIMAGE_DATA_DIRECTORY dllExportDirectory = &dllPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (dllExportDirectory->Size > 0) 
  {
    PIMAGE_EXPORT_DIRECTORY dllExportTable = (PIMAGE_EXPORT_DIRECTORY)lookupRVA(dllData, dllPEHeader, dllExportDirectory->VirtualAddress);
    if (dllExportTable->NumberOfNames != 0 && dllExportTable->NumberOfFunctions != 0) 
    {
      DWORD* dllVAOfNames = (DWORD *) lookupRVA(dllData, dllPEHeader, dllExportTable->AddressOfNames);
      WORD * dllVAOfOrdinals = (WORD *) lookupRVA(dllData, dllPEHeader, dllExportTable->AddressOfNameOrdinals);
      DWORD* dllExportedFunctionPointers = (DWORD*) lookupRVA(dllData, dllPEHeader, dllExportTable->AddressOfFunctions);
      for (DWORD i = 0; i < dllExportTable->NumberOfNames; i++) 
      {
        const char* name = lookupRVA(dllData, dllPEHeader, dllVAOfNames[i]);
        size_t dllSectionOfExportedFunction = 0;
        if (lookupRVA(dllData, dllPEHeader, dllExportedFunctionPointers[dllVAOfOrdinals[i]], &dllSectionOfExportedFunction))
        {
          IMAGE_SYMBOL s;
          s.N.LongName[0] = 0;
          s.N.LongName[1] = DWORD(coffSymbolStringTable.size() + 4);
          s.NumberOfAuxSymbols = 0;
          s.SectionNumber = SHORT(dllSectionOfExportedFunction + 1);
          s.StorageClass = IMAGE_SYM_CLASS_EXTERNAL; //function;
          s.Value = dllExportedFunctionPointers[dllVAOfOrdinals[i]]  - dllSectionHeaders[dllSectionOfExportedFunction].VirtualAddress;
          s.NumberOfAuxSymbols = 0;
          s.Type = IMAGE_SYM_TYPE_NULL | (IMAGE_SYM_DTYPE_FUNCTION << 4); // function
          coffSymbols.push_back(s);
          coffSymbolStringTable.insert(coffSymbolStringTable.end(), name, name + strlen(name) + 1); //we want the null terminator too
        }
      }  
    }
  }

  //Add symbol for DLLMain (so that the app can manually call it)

  size_t dllSectionOfEnterPoint = 0;
  if (lookupRVA(dllData, dllPEHeader, dllPEHeader->OptionalHeader.AddressOfEntryPoint, &dllSectionOfEnterPoint))
  {
    IMAGE_SYMBOL s;
    s.N.LongName[0] = 0;
    s.N.LongName[1] = DWORD(coffSymbolStringTable.size() + 4);
    s.NumberOfAuxSymbols = 0;
    s.SectionNumber = SHORT(dllSectionOfEnterPoint + 1);
    s.StorageClass = IMAGE_SYM_CLASS_EXTERNAL; //function;
    s.Value = dllPEHeader->OptionalHeader.AddressOfEntryPoint - dllSectionHeaders[dllSectionOfEnterPoint].VirtualAddress;
    s.NumberOfAuxSymbols = 0;
    s.Type = IMAGE_SYM_TYPE_NULL | (IMAGE_SYM_DTYPE_FUNCTION << 4); // function
    coffSymbols.push_back(s);

    char terribleStdCallMangledName[1024];
#ifdef _WIN64
    sprintf_s(terribleStdCallMangledName, "%s_DllMain", nameNoPeriod.c_str());
#else
    sprintf_s(terribleStdCallMangledName, "_%s_DllMain@12", nameNoPeriod.c_str());
#endif
    size_t nameLen = strlen(terribleStdCallMangledName);
    coffSymbolStringTable.insert(coffSymbolStringTable.end(), terribleStdCallMangledName, terribleStdCallMangledName + nameLen + 1); //we want the null terminator too

    //write out the nice header
    std::ofstream headerStream((nameNoPeriod + "_Mashed.h").c_str(), std::ios::out);
    headerStream << "extern \"C\"" << std::endl;
    headerStream << "{" << std::endl;

    headerStream << "BOOL WINAPI " << nameNoPeriod << "_DllMain(" << std::endl
      << "\t" << "__in  HINSTANCE hinstDLL," << std::endl
      << "\t" << "__in  DWORD fdwReason," << std::endl
      << "\t" << "__in  LPVOID lpvReserved" << std::endl
      << "\t" << ");" << std::endl;

    headerStream << "}" << std::endl;

    headerStream << std::endl;

    headerStream << "inline void " << nameNoPeriod << "_FakeLoadLibrary() { " << nameNoPeriod << "_DllMain(GetModuleHandle(0), DLL_PROCESS_ATTACH, 0); }" << std::endl;
    headerStream << "inline void " << nameNoPeriod << "_FakeFreeLibrary() { " << nameNoPeriod << "_DllMain(GetModuleHandle(0), DLL_PROCESS_DETACH, 0); }" << std::endl;
    headerStream << std::endl;
  }

  //convert the relocations
  std::vector<std::vector<IMAGE_RELOCATION>> coffRelocationsBySection;
  coffRelocationsBySection.resize(dllPEHeader->FileHeader.NumberOfSections);

  std::map<std::string, std::vector<Import>> dllImportsByImportedDLL;

  PIMAGE_DATA_DIRECTORY dllImportDirectory = &dllPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (dllImportDirectory->Size > 0) 
  {
    PIMAGE_IMPORT_DESCRIPTOR dllImportTable = (PIMAGE_IMPORT_DESCRIPTOR)lookupRVA(dllData, dllPEHeader, dllImportDirectory->VirtualAddress);
    for (; dllImportTable->Name; dllImportTable++)
    {
      char* dllDependencyDLLName = lookupRVA(dllData, dllPEHeader, dllImportTable->Name);
      std::string dllDependencyDLLNameNoPeriod = dllDependencyDLLName;
      std::replace(dllDependencyDLLNameNoPeriod.begin(), dllDependencyDLLNameNoPeriod.end(), '.', '_');
#ifdef _WIN64
      DWORD64 *thunkRef;
#else
      DWORD *thunkRef;
#endif
      FARPROC *dllImportIATs;
      if (dllImportTable->OriginalFirstThunk) {
        thunkRef = (decltype(thunkRef)) lookupRVA(dllData, dllPEHeader, dllImportTable->OriginalFirstThunk);
        dllImportIATs = (FARPROC *) lookupRVA(dllData, dllPEHeader, dllImportTable->FirstThunk);
      } else {
        // no hint table
        thunkRef = (decltype(thunkRef)) lookupRVA(dllData, dllPEHeader, dllImportTable->FirstThunk);
        dllImportIATs = (FARPROC *) lookupRVA(dllData, dllPEHeader, dllImportTable->FirstThunk);
      }
      size_t curImportIdx = 0;
      for (; *thunkRef; thunkRef++, dllImportIATs++, curImportIdx++) {
        Import fakeImportLibImport;
#ifdef _WIN64
        bool isMangled = true;
#else
        bool isMangled = false;
#endif
        if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) 
        {
          fakeImportLibImport.exportOrdinal = IMAGE_ORDINAL(*thunkRef);
          fakeImportLibImport.symbolName = nameNoPeriod + "_" + dllDependencyDLLNameNoPeriod;
          char tempBuff[512];
          sprintf_s(tempBuff, "_Ordinal_%i", fakeImportLibImport.exportOrdinal);
          fakeImportLibImport.symbolName += tempBuff;
        }
        else 
        {
          PIMAGE_IMPORT_BY_NAME dllCurImportName = (PIMAGE_IMPORT_BY_NAME) lookupRVA(dllData, dllPEHeader,  (DWORD)(*thunkRef));
          fakeImportLibImport.exportName = (LPCSTR)&dllCurImportName->Name;
          if (fakeImportLibImport.exportName[0] == '?')
            isMangled = true;

          if (isMangled)
            fakeImportLibImport.symbolName = fakeImportLibImport.exportName;
          else 
            fakeImportLibImport.symbolName = "@" + fakeImportLibImport.exportName + "@" + nameNoPeriod + "_" + dllDependencyDLLNameNoPeriod; //this gets truncated past and before @ by the linker
          fakeImportLibImport.exportOrdinal = 0;
        }

        *dllImportIATs = 0;
        IMAGE_SYMBOL coffSymbolForCurImport;
        coffSymbolForCurImport.N.LongName[0] = 0;
        coffSymbolForCurImport.N.LongName[1] = DWORD(coffSymbolStringTable.size() + 4);
        coffSymbolForCurImport.NumberOfAuxSymbols = 0;
        coffSymbolForCurImport.SectionNumber = IMAGE_SYM_UNDEFINED;
        coffSymbolForCurImport.StorageClass = IMAGE_SYM_CLASS_EXTERNAL; //function;
        //smuggle this here
        coffSymbolForCurImport.Value = DWORD(dllImportTable->FirstThunk + curImportIdx * sizeof(FARPROC) + dllPEHeader->OptionalHeader.ImageBase);// - seHdr[thunkSec].VirtualAddress;
        coffSymbolForCurImport.NumberOfAuxSymbols = 0;
        coffSymbolForCurImport.Type = IMAGE_SYM_TYPE_NULL | (IMAGE_SYM_DTYPE_NULL << 4);
        coffSymbols.push_back(coffSymbolForCurImport);

        coffSymbolStringTable.insert(coffSymbolStringTable.end(), importedSymbolPrefix.begin(), importedSymbolPrefix.end()); //imp prefix is added automatically to the import lib
        coffSymbolStringTable.insert(coffSymbolStringTable.end(), fakeImportLibImport.symbolName.begin(), fakeImportLibImport.symbolName.end()); //we want the null terminator too
        coffSymbolStringTable.push_back(0); //null terminator

        if (!isMangled) //skip mangled names since they don't need weird fixups
          dllImportsByImportedDLL[dllDependencyDLLName].push_back(fakeImportLibImport);
      }
    }
  }


  PIMAGE_DATA_DIRECTORY dllRelcationDirectory = &dllPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  if (dllRelcationDirectory->Size > 0) {
    PIMAGE_BASE_RELOCATION dllCurRelocation = (PIMAGE_BASE_RELOCATION)lookupRVA(dllData, dllPEHeader, dllRelcationDirectory->VirtualAddress);
    while(dllCurRelocation->VirtualAddress > 0) {

      WORD *relInfo = (unsigned short *)((unsigned char *)dllCurRelocation + sizeof(IMAGE_BASE_RELOCATION));
      for (size_t relInBlock = 0; relInBlock < ((dllCurRelocation->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION)) / 2); relInBlock++) {
        // the upper 4 bits define the type of relocation
        int type = relInfo[relInBlock] >> 12;
        // the lower 12 bits define the offset
        int offset = relInfo[relInBlock] & 0xfff;
        IMAGE_RELOCATION coffRelocation;
        coffRelocation.VirtualAddress = dllCurRelocation->VirtualAddress + offset;

        size_t relocationLocationSection = 0;
        //need to check each time. Old code was assuming the entire dllCurRelocation was in one section...which caused the exe to get scrambled
        //with dynamic base mode on
        char* dllRelocationLocation = lookupRVA(dllData, dllPEHeader, coffRelocation.VirtualAddress, &relocationLocationSection);
        if (dllRelocationLocation)
          coffRelocation.VirtualAddress -= dllSectionHeaders[relocationLocationSection].VirtualAddress;
        else
          continue;

        DWORD *patchAddrHL = (DWORD *)(dllRelocationLocation);
#ifdef _WIN64
        DWORD64 *patchAddr64 = (DWORD64 *)(dllRelocationLocation);
#endif
        DWORD64 relocTargetCurVal = 0;

        switch (type)
        {
        case IMAGE_REL_BASED_ABSOLUTE:
          // skip relocation
          continue;

        case IMAGE_REL_BASED_HIGHLOW:
          // change complete 32 bit address
#ifdef _WIN64
          coffRelocation.Type = IMAGE_REL_AMD64_ADDR32;
#else
          coffRelocation.Type = IMAGE_REL_I386_DIR32;
#endif
          relocTargetCurVal = *patchAddrHL;
          *patchAddrHL = 0; //all are zero in obj file, the linker uses the symbols
          break;

#ifdef _WIN64
        case IMAGE_REL_BASED_DIR64:
          coffRelocation.Type = IMAGE_REL_AMD64_ADDR64;
          relocTargetCurVal = *patchAddr64;
          *patchAddr64 = 0; //all are zero in obj file, the linker uses the symbols
          break;
#endif
        default:
          printf("Unknown relocation: %d\n", type);
          continue;
        }

        size_t sy;
        for (sy = 0; sy < coffSymbols.size(); sy++)
        {
          if (coffSymbols[sy].Value == relocTargetCurVal)
          {
            coffRelocation.SymbolTableIndex = DWORD(sy); //the value is ignored for imports but use it match them.
            break;
          }
        }

        size_t relocationValueSection = relocationLocationSection;
        if (sy == coffSymbols.size())
        {
          //can't find it so make bogus one since it was baked out when the DLL was linked
          //Steal the address from the code before we zero it out and make a bogus named "Symbol"
          IMAGE_SYMBOL coffInternalRelocationFakeSymbol;
          coffInternalRelocationFakeSymbol.N.LongName[0] = 0;
          coffInternalRelocationFakeSymbol.N.LongName[1] = DWORD(coffSymbolStringTable.size() + 4);
          coffInternalRelocationFakeSymbol.NumberOfAuxSymbols = 0;

          //if the relocation points to and address that is valid, use that section instead
          if (!lookupRVA(dllData, dllPEHeader, (DWORD)(relocTargetCurVal - dllPEHeader->OptionalHeader.ImageBase), &relocationValueSection, true))
            relocationValueSection = relocationLocationSection;

          coffInternalRelocationFakeSymbol.SectionNumber = SHORT(relocationValueSection + 1);
          coffInternalRelocationFakeSymbol.StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
          coffInternalRelocationFakeSymbol.Value = DWORD((relocTargetCurVal - dllPEHeader->OptionalHeader.ImageBase) - dllSectionHeaders[relocationValueSection].VirtualAddress);
          coffInternalRelocationFakeSymbol.NumberOfAuxSymbols = 0;
          coffInternalRelocationFakeSymbol.Type = IMAGE_SYM_TYPE_NULL | (IMAGE_SYM_DTYPE_NULL << 4);;// not function
          coffRelocation.SymbolTableIndex = DWORD(coffSymbols.size());
          char tempBuf[1024];
          sprintf_s(tempBuf, "__bogus__Reloc%i", (int)coffSymbols.size());
          coffSymbols.push_back(coffInternalRelocationFakeSymbol);
          coffSymbolStringTable.insert(coffSymbolStringTable.end(), tempBuf, tempBuf + strlen(tempBuf) + 1); //we want the null terminator too
        }

        coffRelocationsBySection[relocationLocationSection].push_back(coffRelocation);
      }
      // advance to next relocation block
      dllCurRelocation = (PIMAGE_BASE_RELOCATION) (((char *) dllCurRelocation) + dllCurRelocation->SizeOfBlock);

    }
  }

  for (size_t se = 0; se < coffSectionHeaders.size(); se++)
  {
    IMAGE_SECTION_HEADER& s = coffSectionHeaders[se];
    if (s.PointerToRawData)
    {
      auto curOff = os.tellp();
      std::pair<DWORD,DWORD> p;
      p.first = s.PointerToRawData;
      if (s.PointerToRawData)
        s.PointerToRawData = DWORD(curOff);

      DWORD bytesRemoved =  (p.first - s.PointerToRawData);
      if (s.PointerToLinenumbers)
        s.PointerToLinenumbers -= bytesRemoved;
      if (s.PointerToRelocations)
      {
        std::cout << "Huh?\n";
        s.PointerToRelocations -= bytesRemoved;
      }

      p.second = s.PointerToRawData;
      dllToCoffSectionVAShifts.push_back(p);
#ifdef _WIN64
      if (strcmp((char*)s.Name, ".pdata") == 0)
      {
        ////Add COMDAT symbol
        //IMAGE_SYMBOL coffInternalComdatSym;
        //coffInternalComdatSym.N.LongName[0] = 0;
        //coffInternalComdatSym.N.LongName[1] = coffSymbolStringTable.size() + 4;
        //coffInternalComdatSym.SectionNumber = se + 1;
        //coffInternalComdatSym.StorageClass = IMAGE_SYM_CLASS_STATIC;
        //coffInternalComdatSym.Value = 0;
        //coffInternalComdatSym.NumberOfAuxSymbols = 1;
        //coffInternalComdatSym.Type = IMAGE_SYM_TYPE_NULL | (IMAGE_SYM_DTYPE_NULL << 4);// not function
        //coffSymbols.push_back(coffInternalComdatSym);
        //const std::string comdatSymbol1(".pdata");
        //coffSymbolStringTable.insert(coffSymbolStringTable.end(), comdatSymbol1.begin(), comdatSymbol1.end());
        ////we want the null terminator too
        //coffSymbolStringTable.push_back(0);


        ////make AUX symbol for COMDAT
        //IMAGE_AUX_SYMBOL auxSymbol;
        ////Why is this just duplicate data?
        //auxSymbol.Section.Length = s.SizeOfRawData;
        //auxSymbol.Section.NumberOfRelocations = s.NumberOfRelocations;
        //auxSymbol.Section.NumberOfLinenumbers = s.NumberOfLinenumbers;
        //auxSymbol.Section.CheckSum = 0;
        //auxSymbol.Section.Number = textSection + 1; //assume code is in .text which is true for MS binaries
        //auxSymbol.Section.Selection = IMAGE_COMDAT_SELECT_ASSOCIATIVE;
        ////they are the same size because this format is terrible
        //coffSymbols.push_back(*((IMAGE_SYMBOL*)&coffInternalComdatSym));

        ////number 2 to satisfy the department of redundancy department
        //coffInternalComdatSym.N.LongName[1] = coffSymbolStringTable.size() + 4;
        //coffInternalComdatSym.NumberOfAuxSymbols = 0;
        //coffSymbols.push_back(coffInternalComdatSym);
        //const std::string comdatSymbol2("$pdata$COMDAT");
        //coffSymbolStringTable.insert(coffSymbolStringTable.end(), comdatSymbol2.begin(), comdatSymbol2.end());
        ////we want the null terminator too
        //coffSymbolStringTable.push_back(0);
        //s.Characteristics |= IMAGE_SCN_LNK_COMDAT;


        assert(s.VirtualAddress == dllPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

        DWORD count = dllPEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / 12;
        //trim extra bullshit
        s.SizeOfRawData = count * 12;
        PIMAGE_FUNCTION_ENTRY pdataList = (PIMAGE_FUNCTION_ENTRY)lookupRVA(dllData, dllPEHeader, s.VirtualAddress);
        //need to fix up crap
        for (DWORD entry = 0; entry < count; entry++)
        {
          IMAGE_FUNCTION_ENTRY ui = pdataList[entry];
          size_t entrySection = 0, unwindSection = 0;
          if (lookupRVA(dllData, dllPEHeader, ui.StartingAddress, &entrySection, true))
            ui.StartingAddress -= dllSectionHeaders[entrySection].VirtualAddress;
          if (lookupRVA(dllData, dllPEHeader, ui.EndingAddress, &entrySection, true))
            ui.EndingAddress -= dllSectionHeaders[entrySection].VirtualAddress;
          DWORD unwindDataVA = ui.EndOfPrologue;
          if (lookupRVA(dllData, dllPEHeader, ui.EndOfPrologue, &unwindSection, true))
            unwindDataVA -= dllSectionHeaders[unwindSection].VirtualAddress;

          DWORD entryStartVA = ui.StartingAddress;
          //sanitize it
          ui.EndingAddress -= ui.StartingAddress;
          ui.StartingAddress = 0;
          ui.EndOfPrologue = 0;
          os.write((char*)&ui, sizeof(ui));

          IMAGE_SYMBOL coffUnwindLabelSymbol;
          DWORD coffUnwindLabelIdx = DWORD(coffSymbols.size());
          coffUnwindLabelSymbol.N.LongName[0] = 0;
          coffUnwindLabelSymbol.N.LongName[1] = DWORD(coffSymbolStringTable.size() + 4);
          coffUnwindLabelSymbol.NumberOfAuxSymbols = 0;

          coffUnwindLabelSymbol.SectionNumber = SHORT(entrySection + 1);
          coffUnwindLabelSymbol.StorageClass = IMAGE_SYM_CLASS_LABEL;
          coffUnwindLabelSymbol.Value = entryStartVA;
          coffUnwindLabelSymbol.NumberOfAuxSymbols = 0;
          coffUnwindLabelSymbol.Type = IMAGE_SYM_TYPE_NULL | (IMAGE_SYM_DTYPE_NULL << 4);// not function
          char tempBuf[1024];
          sprintf_s(tempBuf, "$LN%i", (int)entry);
          coffSymbols.push_back(coffUnwindLabelSymbol);
          coffSymbolStringTable.insert(coffSymbolStringTable.end(), tempBuf, tempBuf + strlen(tempBuf) + 1); //we want the null terminator too

          IMAGE_SYMBOL coffUnwindSymbol;
          DWORD coffUnwindIdx = DWORD(coffSymbols.size());
          coffUnwindSymbol.N.LongName[0] = 0;
          coffUnwindSymbol.N.LongName[1] = DWORD(coffSymbolStringTable.size() + 4);
          coffUnwindSymbol.NumberOfAuxSymbols = 0;

          coffUnwindSymbol.SectionNumber = SHORT(unwindSection + 1);
          coffUnwindSymbol.StorageClass = IMAGE_SYM_CLASS_STATIC;
          coffUnwindSymbol.Value = unwindDataVA;
          coffUnwindSymbol.NumberOfAuxSymbols = 0;
          coffUnwindSymbol.Type = IMAGE_SYM_TYPE_NULL | (IMAGE_SYM_DTYPE_NULL << 4);// not function
          sprintf_s(tempBuf, "$unwind$%i", (int)entry);
          coffSymbols.push_back(coffUnwindSymbol);
          coffSymbolStringTable.insert(coffSymbolStringTable.end(), tempBuf, tempBuf + strlen(tempBuf) + 1); //we want the null terminator too

          IMAGE_RELOCATION coffRelocation;
          coffRelocation.Type = IMAGE_REL_AMD64_ADDR32NB;
          coffRelocation.SymbolTableIndex = coffUnwindLabelIdx;
          coffRelocation.VirtualAddress = sizeof(IMAGE_FUNCTION_ENTRY)*entry;
          coffRelocationsBySection[se].push_back(coffRelocation);

          coffRelocation.VirtualAddress = sizeof(IMAGE_FUNCTION_ENTRY)*entry + 4;
          coffRelocationsBySection[se].push_back(coffRelocation);

          coffRelocation.SymbolTableIndex = coffUnwindIdx;
          coffRelocation.VirtualAddress = sizeof(IMAGE_FUNCTION_ENTRY)*entry + 8;
          coffRelocationsBySection[se].push_back(coffRelocation);

        }
      }
      else
      {
        os.write(dllData + p.first, s.SizeOfRawData);
      }
#else
      os.write(dllData + p.first, s.SizeOfRawData);
#endif
    }
    else
    {
      dllToCoffSectionVAShifts.push_back(std::pair<DWORD,DWORD>(0,0));
    }
  }


  auto coffSymbolTableOffset = os.tellp(); //wrote sections


  coffFileHeader.NumberOfSymbols = DWORD(coffSymbols.size());
  if (coffSymbols.size())
  {
    coffFileHeader.PointerToSymbolTable = (DWORD)coffSymbolTableOffset;
    //re-write hdr
    os.seekp(0);
    os.write((char*)&coffFileHeader, sizeof(coffFileHeader));
    os.seekp(coffSymbolTableOffset);
    for (size_t sy = 0; sy < coffSymbols.size(); sy++)
    {
      if (coffSymbols[sy].SectionNumber == IMAGE_SYM_UNDEFINED)
        coffSymbols[sy].Value = 0;
      os.write((char*)&coffSymbols[sy], sizeof(IMAGE_SYMBOL));
    }
    DWORD stringTableSz = DWORD(coffSymbolStringTable.size() + 4);
    os.write((char*)&stringTableSz, 4);
    os.write(coffSymbolStringTable.data(), coffSymbolStringTable.size());
  }

  //Write relocations
  for (size_t se = 0; se < coffSectionHeaders.size(); se++)
  {
    IMAGE_SECTION_HEADER& s = coffSectionHeaders[se];
    if (coffRelocationsBySection[se].size())
    {
      s.PointerToRelocations = (DWORD)os.tellp();
      s.NumberOfRelocations = WORD(coffRelocationsBySection[se].size());
      for (size_t j = 0; j < coffRelocationsBySection[se].size(); j++)
      {
        os.write((char*)&coffRelocationsBySection[se][j].VirtualAddress, sizeof(coffRelocationsBySection[se][j].VirtualAddress));
        os.write((char*)&coffRelocationsBySection[se][j].SymbolTableIndex, sizeof(coffRelocationsBySection[se][j].SymbolTableIndex));
        os.write((char*)&coffRelocationsBySection[se][j].Type, sizeof(coffRelocationsBySection[se][j].Type));
      }
    }
    else
    {
      s.PointerToRelocations = 0;
      s.NumberOfRelocations = 0;
    }
    s.Characteristics |= IMAGE_SCN_ALIGN_1BYTES; //lazy and it's not so important to be better aligned
    s.VirtualAddress = 0; //not used in COFF files
    s.Misc.VirtualSize = 0;
  }

  //write the section hdrs
  coffSymbolTableOffset = os.tellp();
  os.seekp(coffSectionHeaderFileOffset);
  for (size_t se = 0; se < coffSectionHeaders.size(); se++)
  {
    IMAGE_SECTION_HEADER& s = coffSectionHeaders[se];
    if (strcmp((char*)s.Name, ".reloc") == 0)
      memcpy(s.Name, ".oldrel", 8); //don't want two relocation sections, the linker will make a new one, but also don't want offset adjustment hell
    else if (strcmp((char*)s.Name, ".idata") == 0)
      memcpy(s.Name, ".oldimp", 8); //don't want two relocation sections, the linker will make a new one, but also don't want offset adjustment hell
    else if (strcmp((char*)s.Name, ".rsrc") == 0)
      memcpy(s.Name, ".oldrsr", 8); //don't want two relocation sections, the linker will make a new one, but also don't want offset adjustment hell
    os.write((char*)&s, sizeof(IMAGE_SECTION_HEADER));
  }
  os.seekp(coffSymbolTableOffset);

  os.close();
  std::string libCmdLine = "\"C:\\Program Files (x86)\\Microsoft Visual Studio 10.0\\VC\\bin\\vcvars32.bat\" && lib.exe /out:" + nameNoPeriod + ".lib " + intermeddiateObj;
#ifdef _WIN64
  //names are not crazy mangled on x64 it seems
#else
  os.open(intermeddiateImportLib.c_str(), std::ios::binary | std::ios::out);
  os.write(IMAGE_ARCHIVE_START, IMAGE_ARCHIVE_START_SIZE);

  for (auto i = dllImportsByImportedDLL.begin(); i != dllImportsByImportedDLL.end(); i++)
  {
    for (auto j = i->second.begin(); j != i->second.end(); j++)
    {
      Import& curImport = *j;
      const std::string& curImportModuleName = i->first;
      DLLImportPseudoCOFFObject irec;
      memset(&irec, 0, sizeof(DLLImportPseudoCOFFObject));
      irec.Sig1 = IMAGE_FILE_MACHINE_UNKNOWN;
      irec.Sig2 = 0xFFFF;
      irec.Version = 0;
      irec.Machine = dllPEHeader->FileHeader.Machine;
      irec.SizeOfData = (curImport.symbolName.size() + curImportModuleName.size() + 2);
      irec.Ordinal = curImport.exportOrdinal;
      irec.Flags = (0 << 0) | //code
        ((curImport.exportOrdinal == 0 ? 3 : 0) << 2); //ordinal vs name
      //3 = IMPORT_NAME_UNDECORATE which chops at the last @, we can use this to make our names unique so that two mashed dlls don't conflict

      ARArchiveItemHeader item;
      memset(&item, 0, sizeof(ARArchiveItemHeader));
      item.End[0] = 0x60;
      item.End[1] = 0x0A;
      strcpy(item.Name, curImportModuleName.c_str());
      strcat(item.Name, "/");
      strcpy(item.Date, "123"); //bogus date
      strcpy(item.Mode, "777"); //all permissions
      sprintf(item.Size, "%i", int(sizeof(DLLImportPseudoCOFFObject) + irec.SizeOfData));

      os.write((char*)&item, sizeof(item));
      os.write((char*)&irec, sizeof(irec));
      os.write(curImport.symbolName.c_str(), curImport.symbolName.size() + 1);
      os.write(curImportModuleName.c_str(), curImportModuleName.size()+1);
      if (os.tellp() % 2)
        os.put(0); //2 byte aligned
    }
  }
  os.close();

  //combine both into single .lib and generate index header
  libCmdLine += " ";
  libCmdLine += intermeddiateImportLib;
#endif
  int ret = system(libCmdLine.c_str());
  if (ret == 0)
  {
    DeleteFileA(intermeddiateObj.c_str());
    DeleteFileA(intermeddiateImportLib.c_str());
  }
  return ret;
}


