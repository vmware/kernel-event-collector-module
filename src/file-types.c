// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "file-types.h"


//
//  To support ENT-1329, we are trying to determine the type of the file from the existence of a matching
//  "magic" number.  Would like to revisit this at some point to create a more scalable approach (in the
//  likely case that we add more types)!  Something along the line of a tree-walk maybe.
//
//
//  We are splitting up the EICAR test signature to prevent virus scanners from detecting it in our image.
//
static const char *EICAR_TEST_FILE_2 = "!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
static const char *EICAR_TEST_FILE_1 = "X5O";

/*
 * @brief queried a file write window to look for the existence of a file that we are interestd in
 *
 * @param[in] currentData - the current callback data from the write notification
 * @param[inout] pFileType - a pointer to a dword that will contain the file type
 * @param[in] determineDataFiles - whether or not to try to determine data file types
 *
 * @return returns a BOOL specifying whether or not the method succeeded
 */
void determine_file_type(char *buffer, uint32_t bytes_read, CB_FILE_TYPE *pFileType, bool determineDataFiles)
{
    // Check if it's 32 or 64 bit ELF and parse it accordingly
    if (buffer[EI_CLASS] == ELFCLASS32)
    {
        Elf32_Ehdr *elf32 = (Elf32_Ehdr *)buffer;

        if (elf32->e_ident[EI_MAG0] == ELFMAG0 &&
           elf32->e_ident[EI_MAG1] == ELFMAG1 &&
           elf32->e_ident[EI_MAG2] == ELFMAG2 &&
           elf32->e_ident[EI_MAG3] == ELFMAG3 &&
           ((elf32->e_type == ET_EXEC) || (elf32->e_type == ET_DYN)))
        {
            *pFileType = filetypeElf;
            return;
        }
    } else if (buffer[EI_CLASS] == ELFCLASS64)
    {
        Elf64_Ehdr *elf64 = (Elf64_Ehdr *)buffer;

        if (elf64->e_ident[EI_MAG0] == ELFMAG0 &&
           elf64->e_ident[EI_MAG1] == ELFMAG1 &&
           elf64->e_ident[EI_MAG2] == ELFMAG2 &&
           elf64->e_ident[EI_MAG3] == ELFMAG3 &&
           ((elf64->e_type == ET_EXEC) || (elf64->e_type == ET_DYN)))
        {
            *pFileType = filetypeElf;
            return;
        }
    }

    //
    //  We are always looking for PE files and EICAR files
    //
    if (bytes_read >= 2)
    {
        if (memcmp("MZ", buffer, 2) == 0)
        {
            *pFileType = filetypePe;
            return;
        }
    }
    if (bytes_read >= MAX_FILE_BYTES_TO_DETERMINE_TYPE)
    {
        if (memcmp(EICAR_TEST_FILE_1, buffer, 3) == 0)
        {
            pr_info("Fount EICAR PRE\n");
            if (memcmp(EICAR_TEST_FILE_2, buffer + 3, MAX_FILE_BYTES_TO_DETERMINE_TYPE - 3) == 0)
            {
                *pFileType = filetypeEicar;
                return;
            }
        }
    }

    //
    //  We are looking for data files dependent on configuration
    //
    if (determineDataFiles)
    {
        if (bytes_read >= 2)
        {
            if (memcmp("MZ", buffer, 2) == 0)
            {
                *pFileType = filetypePe;
                return;
            }
            if (memcmp("\x1F\xA0", buffer, 2) == 0)
            {
                *pFileType = filetypeArchiveLzh;
                return;
            }
            if (memcmp("\x1F\x9D", buffer, 2) == 0)
            {
                *pFileType = filetypeArchiveLzw;
                return;
            }
        }
        if (bytes_read >= 4)
        {
            if (memcmp("\x25\x50\x44\x46", buffer, 4) == 0)
            {
                *pFileType = filetypePdf;
                return;
            }
            if (memcmp("\x50\x4B\x03\x04", buffer, 4) == 0)
            {
                if (bytes_read >= 8 && memcmp("\x50\x4B\x03\x04\x14\x00\x06\x00", buffer, 8) == 0)
                {
                    *pFileType = filetypeOfficeOpenXml;
                    return;
                } else
                {
                    *pFileType = filetypeArchivePkzip;
                    return;
                }
            }
            if (memcmp("\x50\x4B\x05\x06", buffer, 4) == 0 ||
                memcmp("\x50\x4B\x07\x08", buffer, 4) == 0)
            {
                *pFileType = filetypeArchivePkzip;
                return;
            }
            if (memcmp("\xD0\xCF\x11\xE0", buffer, 4) == 0)
            {
                *pFileType = filetypeOfficeLegacy;
                return;
            }
        }
        if (bytes_read >= 5)
        {
            if (memcmp("\x75\x73\x74\x61\x72", buffer, 5) == 0)
            {
                *pFileType = filetypeArchiveTar;
                return;
            }
        }
        if (bytes_read >= 6)
        {
            if (memcmp("\x37\x7A\xBC\xAF\x27\x1C", buffer, 6) == 0)
            {
                *pFileType = filetypeArchive7zip;
                return;
            }
        }
        if (bytes_read >= 7)
        {
            if (memcmp("\x52\x61\x72\x21\x1A\x07\x00", buffer, 7) == 0)
            {
                *pFileType = filetypeArchiveRar;
                return;
            }
        }
    }


    *pFileType = filetypeUnknown;
}

char *file_type_str(CB_FILE_TYPE fileType)
{
    char *ret = NULL;

    switch (fileType)
    {;
    case filetypePe:
    case filetypeElf:
    case filetypeUniversalBin: ret = "Binary"        ; break;
    case filetypeEicar: ret = "Eicar"         ; break;
    case filetypeOfficeLegacy: ret = "OfficeLegacy"  ; break;
    case filetypeOfficeOpenXml: ret = "OfficeOpenXml" ; break;
    case filetypePdf: ret = "Pdf"           ; break;
    case filetypeArchivePkzip: ret = "ArchivePkzip"  ; break;
    case filetypeArchiveLzh: ret = "ArchiveLzh"    ; break;
    case filetypeArchiveLzw: ret = "ArchiveLzw"    ; break;
    case filetypeArchiveRar: ret = "ArchiveRar"    ; break;
    case filetypeArchiveTar: ret = "ArchiveTar"    ; break;
    case filetypeArchive7zip: ret = "Archive7zip"   ; break;
    default:
    case filetypeUnknown: ret = "Unknown"       ; break;
    }
    return ret;
}
