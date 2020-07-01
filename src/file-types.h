//
//  file-types.h
//
//  Ported from OSX on 05/17/16.
//
//

#ifndef __CbOsxSensor__file_types__
#define __CbOsxSensor__file_types__

#define MAX_FILE_BYTES_TO_DETERMINE_TYPE 68

void  determine_file_type(char *buffer, uint32_t bytes_read, CB_FILE_TYPE *pFileType, bool determineDataFiles);
char *file_type_str(CB_FILE_TYPE fileType);


#endif /* defined(__CbOsxSensor__file_types__) */
