//
// Copyright (c) 2018 Carbon Black. All rights reserved.
//

#ifndef CBR_LINUX_INODESTATE_H
#define CBR_LINUX_INODESTATE_H

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum {
        InodeUnknown = 0,
        InodeAllowed = 1,
        InodeBanned  = 2
    } InodeState;

#ifdef __cplusplus
}
#endif

#endif //CBR_LINUX_INODESTATE_H
