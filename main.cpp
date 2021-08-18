#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <windows.h>
#include <winnt.h>
#include <vector>

using namespace std;

struct PESection {
    IMAGE_SECTION_HEADER *Header;
    unsigned char *Data;
};

class PE {
    private:
        int getFileSize(FILE *file) {
            fseek(file, 0L, SEEK_END);
            long int file_size = ftell(file);
            fseek(file, 0L, SEEK_SET);

            return file_size;
        }

        void Padding(FILE *f, size_t end) {
            static BYTE Zero[1];

            if(ftell(f) >= end) {
                return;
            }

            while(ftell(f) < end) {
                fwrite(Zero, 1, sizeof(Zero), f);
            }
        }

    public:
        unsigned char *Binary;
        IMAGE_DOS_HEADER *DOS_HEADER;
        IMAGE_NT_HEADERS *NT_HEADERS;

        vector<PESection *> Sections;

        bool Load(const char *path) {
            FILE *f = fopen(path, "rb");

            if(!f) {
                puts("[!] Opening a file failed!");
                return false;
            }

            long int sizeOfFile = getFileSize(f);

            Binary = new unsigned char[sizeOfFile+1];

            size_t size = fread(Binary, 1, sizeOfFile, f);

            if(size != sizeOfFile) {
                printf("[!] Size of file (%d) and number of bytes read (%d) doesn't match\n", sizeOfFile, size);
                return false;
            }

            DOS_HEADER = (IMAGE_DOS_HEADER*)Binary;
            NT_HEADERS = (IMAGE_NT_HEADERS*) (((char*) DOS_HEADER) + DOS_HEADER->e_lfanew);

            if(DOS_HEADER->e_magic != 0x5a4d || NT_HEADERS->Signature != 0x4550) { // check signatures
                printf("This is not a PE file");
                return false;
            }

            PESection *Section = new PESection;
            Section->Header = (IMAGE_SECTION_HEADER*) (NT_HEADERS + 1);

            Section->Data = new unsigned char[Section->Header->SizeOfRawData];
            Section->Data = &Binary[Section->Header->PointerToRawData];

            Sections.push_back(Section);

            for(int i = 0; i < NT_HEADERS->FileHeader.NumberOfSections-1; i++) {
                PESection *Section = new PESection;
                Section->Header = (IMAGE_SECTION_HEADER*) (Sections[i]->Header + 1);

                Section->Data = new unsigned char[Section->Header->SizeOfRawData];
                Section->Data = &Binary[Section->Header->PointerToRawData];


                Sections.push_back(Section);
            }

            fclose(f);
            return true;
        }

        bool Dump(const char *name) {
            FILE *f = fopen(name, "wb");

            if(!f) {
                puts("[!] Opening a file failed!");
                return false;
            }
            fwrite(DOS_HEADER, 1, sizeof(*DOS_HEADER), f);
            Padding(f, DOS_HEADER->e_lfanew);
            fwrite(NT_HEADERS, 1, sizeof(*NT_HEADERS), f);

            for(int i = 0; i < NT_HEADERS->FileHeader.NumberOfSections; i++) {
                fwrite(Sections[i]->Header, 1, sizeof(*Sections[i]->Header), f);
            }

            Padding(f, Sections[0]->Header->PointerToRawData);

            for(int i = 0; i < NT_HEADERS->FileHeader.NumberOfSections; i++) {
                fwrite(Sections[i]->Data, 1, Sections[i]->Header->SizeOfRawData, f);
            }

            fclose(f);
            return true;
        }

        void AddSection(const char *name, unsigned char *data, int SizeOfRawData, int VirtualSize) {
            int lstSecIndex = Sections.size()-1;
            int numberOfPages = 
                (Sections[lstSecIndex]->Header->VirtualAddress)/4096;
            int sizeOfLastPage = 
                (Sections[lstSecIndex]->Header->Misc.VirtualSize)/4096 + 1;
            int RVA = (numberOfPages + sizeOfLastPage) * 4096;

            PESection *mySection = new PESection;
            Sections.push_back(mySection);

            NT_HEADERS->FileHeader.NumberOfSections += 1;
            NT_HEADERS->OptionalHeader.SizeOfImage += 4096;

            memcpy(mySection->Header->Name, name, strlen(name));
            mySection->Header->SizeOfRawData = SizeOfRawData;
            mySection->Header->Misc.VirtualSize = VirtualSize;
            mySection->Data = data;
            mySection->Header->PointerToRawData = 
                (Sections[lstSecIndex]->Header->PointerToRawData) +
                (Sections[lstSecIndex]->Header->SizeOfRawData);
            mySection->Header->VirtualAddress = (DWORD)RVA;
            mySection->Header->Characteristics = 
                IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ |
                IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE |
                IMAGE_SCN_CNT_INITIALIZED_DATA;
        }

};

int main() {

    char filename[64];
    char loadername[64];

    PE file;

    printf("Filename: ");
    scanf("%57s", &filename);
    printf("Filename: ");
    scanf("%57s", &loadername);

    if(file.Load((const char*)filename) != true) {
        printf("Unable to load a file");
        return 1;
    }

    unsigned char *sectionBody = new unsigned char[4096];

    memset(sectionBody, 0, 4096);

    FILE *f = fopen(loadername, "rb");
    size_t ret = fread(sectionBody, 1, 0x1000, f);
    fclose(f);

    file.AddSection("myPacker", sectionBody, 4096, 4096);

    DWORD OEP = file.NT_HEADERS->OptionalHeader.AddressOfEntryPoint + file.NT_HEADERS->OptionalHeader.ImageBase;
    DWORD SecAddr = file.Sections[0]->Header->VirtualAddress + file.NT_HEADERS->OptionalHeader.ImageBase;
    DWORD SecSize = file.Sections[0]->Header->SizeOfRawData;

    memcpy(sectionBody, &OEP, 4);
    memcpy(&sectionBody[4], &SecAddr, 4);
    memcpy(&sectionBody[8], &SecSize, 4);

    file.NT_HEADERS->OptionalHeader.AddressOfEntryPoint = file.Sections[file.Sections.size()-1]->Header->VirtualAddress + 24;

    for(int i = 0; i < file.Sections[0]->Header->SizeOfRawData; i++) {
        file.Sections[0]->Data[i] ^= 85;
    }

    file.Sections[0]->Header->Characteristics |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ;

    filename[strlen(filename)-4] = '\0';
    file.Dump(strcat(filename, "Packed.exe"));

    return 0;
}
