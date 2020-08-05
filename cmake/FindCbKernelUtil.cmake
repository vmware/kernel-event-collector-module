# Copyright 2018 Carbon Black Inc.  All rights reserved.

function(cb_add_kernel_module)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(FATAL_ERROR "You could only build linux kernel module on a linux system. Current system: ${CMAKE_SYSTEM_NAME}")
    endif()

    set(options           USE_NATIVE_COMPILER)
    set(oneValueArgs      NAME KERNEL_NAME KERNEL_VERSION MODULE_SOURCE_DIR KERNEL_BUILD_DIR VERBOSE OUTPUT_PATH EXTRA_SYMBOLS)
    set(multiValueArgs    SOURCE_FILES FLAGS AFLAGS)
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT ARG_NAME)
        message(FATAL_ERROR "You must give a name to the module")
    else()
        string(TOLOWER ${ARG_NAME} MODULE_NAME)
    endif()

    if(NOT ARG_MODULE_SOURCE_DIR)
        set(MODULE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
    else()
        set(MODULE_SOURCE_DIR ${ARG_MODULE_SOURCE_DIR})
    endif()

    if(NOT ARG_KERNEL_NAME)
        message(FATAL_ERROR "You must give a kernel version")
    else()
        set(CURRENT_KERNEL_NAME ${ARG_KERNEL_NAME})
    endif()

    if(ARG_OUTPUT_PATH)
        set(OUTPUT_PATH ${ARG_OUTPUT_PATH})
    endif()

    set(KBUILD_DIR ${MODULE_SOURCE_DIR})

    if(ARG_KERNEL_VERSION)
        set(OUTPUT_SUFFIX .${ARG_KERNEL_VERSION})
        set(TARGET_SUFFIX -${ARG_KERNEL_VERSION})
        set(KBUILD_DIR ${KBUILD_DIR}/${ARG_KERNEL_VERSION})
    endif()

    set(KBUILD_FILE ${KBUILD_DIR}/Kbuild)

    if(ARG_VERBOSE)
        set(_VERBOSE 1)
    else()
        set(_VERBOSE 0)
    endif()

    if(ARG_SOURCE_FILES)
        foreach(f ${ARG_SOURCE_FILES})
            string(REGEX MATCH "^[^ ]+\\.[cS]$" MATCHES ${f})
            if(MATCHES)
                list(APPEND MODULE_SOURCE_FILES ${f})
                if("${MODULE_NAME}.c" STREQUAL "${f}")
                    message(FATAL_ERROR "${f}: when there are multiple source modules a source file cannot have the same name as the module")
                endif()
                string(REGEX REPLACE "\\.[cS]" ".o" fo ${f})
                set(MODULE_OBJECT_FILES "${MODULE_OBJECT_FILES} ${fo}")
                list(APPEND OUTPUT_OBJS ${fo})
                string(REGEX MATCH "^.+/" subdir ${f})
                list(APPEND SUBDIRS ${subdir})
            endif()
        endforeach()
    endif()
    list(APPEND OUTPUT_OBJS ${MODULE_NAME}.mod.c
            ${MODULE_NAME}.mod.o
            ${MODULE_NAME}.o
            modules.order
            Module.symvers)

    list(LENGTH SUBDIRS SUBDIRS_LEN)
    if (${SUBDIRS_LEN} GREATER 0)
        list(REMOVE_DUPLICATES SUBDIRS)
        foreach(subdir ${SUBDIRS})
            list(APPEND MKSUBDIRS_COMMANDS COMMAND mkdir ${subdir})
        endforeach()
    endif()

    if(ARG_FLAGS)
        foreach(f ${ARG_FLAGS})
            set(MODULE_FLAGS "${MODULE_FLAGS} ${f}")
        endforeach()
    endif()

    if(ARG_AFLAGS)
        foreach(f ${ARG_AFLAGS})
            set(ASM_FLAGS "${ASM_FLAGS} ${f}")
        endforeach()
    endif()

    if(ARG_KERNEL_BUILD_DIR)
        set(KERNEL_BUILD_DIR ${ARG_KERNEL_BUILD_DIR})
    else()
        set(KERNEL_BUILD_DIR "/lib/modules/${CURRENT_KERNEL_NAME}/build")
    endif()

    file(WRITE ${KBUILD_FILE} "obj-m := ${MODULE_NAME}.o\n")

    set(MODULE_FLAGS "${MODULE_FLAGS} -I${MODULE_SOURCE_DIR}")
    if(MODULE_FLAGS)
        file(APPEND ${KBUILD_FILE}
                "ccflags-y := ${MODULE_FLAGS}\n")
    endif()

    if(ASM_FLAGS)
        file(APPEND ${KBUILD_FILE}
                "asflags-y := ${ASM_FLAGS}\n")
    endif()

    if(MODULE_OBJECT_FILES)
        file(APPEND ${KBUILD_FILE}
                "${MODULE_NAME}-objs := ${MODULE_OBJECT_FILES}\n")
    endif()

    # If there are any symvers files added from another module, include it now
    if(ARG_EXTRA_SYMBOLS)
        file(APPEND ${KBUILD_FILE}
                "KBUILD_EXTRA_SYMBOLS = ${ARG_EXTRA_SYMBOLS}\n")
    endif()

    # Decide on what compiler to use.
    #  We may want to use the default system toolchain and not the one provided
    #  in the profile.  This is by design since it needs to use the same compiler
    #  as the running kernel.
    if(ARG_USE_NATIVE_COMPILER)
        set(_CC gcc)
    else()
        set(_CC ${CMAKE_C_COMPILER})
    endif()

    # Override CC in the Kbuild file
    string(REPLACE ";" " " _LNCH "${CMAKE_C_COMPILER_LAUNCHER}")
    file(APPEND ${KBUILD_FILE}
            "CC=${_LNCH} ${_CC}\n")


    set(MODULE_BIN_NAME ${MODULE_NAME}.ko)
    set(MODULE_SYMVER_NAME Module.symvers)

    set(OUTPUT_BIN_NAME    ${MODULE_BIN_NAME}${OUTPUT_SUFFIX})
    set(OUTPUT_SYMVER_NAME ${MODULE_NAME}.symvers${OUTPUT_SUFFIX})

    set(CLONE_KBUILD_COMMAND cp -n ${KBUILD_FILE} ${MODULE_SOURCE_DIR} &> /dev/null || true)
    set(KBUILD_COMMAND $(MAKE) --no-print-directory -C ${KERNEL_BUILD_DIR} M=${KBUILD_DIR} src=${MODULE_SOURCE_DIR} o=${KBUILD_DIR} V=${_VERBOSE})

    if(OUTPUT_PATH)
        set(OUTPUT_BIN_NAME    "${OUTPUT_PATH}/${OUTPUT_BIN_NAME}")
        set(OUTPUT_SYMVER_NAME "${OUTPUT_PATH}/${OUTPUT_SYMVER_NAME}")
        set(MODULE_INSTALL_COMMAND mkdir -p ${OUTPUT_PATH} && mv ${MODULE_BIN_NAME} ${OUTPUT_BIN_NAME} && mv ${MODULE_SYMVER_NAME} ${OUTPUT_SYMVER_NAME})
        set(SYMBOLS_INSTALL_COMMAND objcopy --only-keep-debug ${OUTPUT_BIN_NAME} ${OUTPUT_BIN_NAME}.debug && ${CMAKE_STRIP} --strip-unneeded ${OUTPUT_BIN_NAME})
    endif()

    add_custom_command(OUTPUT ${OUTPUT_BIN_NAME} ${OUTPUT_SYMVER_NAME} ${KERNEL_BUILD_DIR}/${MODULE_BIN_NAME}
            ${MKSUBDIRS_COMMANDS}
            COMMAND ${CLONE_KBUILD_COMMAND}
            COMMAND ${KBUILD_COMMAND} modules
            COMMAND ${MODULE_INSTALL_COMMAND}
            COMMAND ${SYMBOLS_INSTALL_COMMAND}
            VERBATIM
            WORKING_DIRECTORY ${KBUILD_DIR}
            COMMENT "Generating ${MODULE_BIN_NAME}${OUTPUT_SUFFIX}, ${MODULE_SYMVER_NAME}${OUTPUT_SUFFIX}"
            USES_TERMINAL)

    add_custom_target(modules-${MODULE_NAME}${TARGET_SUFFIX} ALL
            DEPENDS ${OUTPUT_BIN_NAME} ${OUTPUT_SYMVER_NAME} ${KERNEL_BUILD_DIR}/${MODULE_BIN_NAME})
endfunction()

function(cb_check_kernel_files)
    set(options           )
    set(oneValueArgs      SOURCE_DIR)
    set(multiValueArgs    SOURCE_FILES IGNORE_TAGS NEW_TYPES)
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(ARG_IGNORE_TAGS)
        string(REPLACE ";" "," TAGS "${ARG_IGNORE_TAGS}")
        set(IGNORE_OPTION "--ignore=${TAGS}")
    endif()

    if(ARG_NEW_TYPES)
        set(TYPEDEF_FILE "${ARG_SOURCE_DIR}/typedef_file")
        file(WRITE ${TYPEDEF_FILE} "")
        foreach(TYPE ${ARG_NEW_TYPES})
            file(APPEND ${TYPEDEF_FILE} "${TYPE}\n")
        endforeach()
        set(NEW_TYPES_OPTION "--typedefsfile=${TYPEDEF_FILE}")
    endif()

    if(ARG_SOURCE_FILES)
        # Loop over each input source file and construct a command to process it
        foreach(FILE ${ARG_SOURCE_FILES})
            # Build the command string
            set(COMMAND perl $ENV{BUILD_UTIL_DIR}/checkpatch/checkpatch.pl
                    ${IGNORE_OPTION}
                    ${NEW_TYPES_OPTION}
                    --no-summary
                    --max-line-length=200
                    -f
                    --no-tree
                    --terse
                    ${FILE})
            # Create a fake target output file so that a file will only be checked when changes are detected
            string(REPLACE "/" "" TARGET "${FILE}")
            string(PREPEND TARGET ".")
            add_custom_command(OUTPUT ${TARGET}
                    COMMAND export LANG=C
                    COMMAND ${COMMAND}
                    COMMAND touch ${TARGET}
                    DEPENDS ${FILE}
                    VERBATIM
                    WORKING_DIRECTORY ${ARG_SOURCE_DIR}
                    COMMENT "Checking ${FILE}"
                    USES_TERMINAL)

            # The list of the target names for each source file
            list(APPEND DEPS ${TARGET})
        endforeach()

        # Top level target that will cause all files to be processed
        add_custom_target(check-kernel-files ALL
                DEPENDS ${DEPS})
    endif()
endfunction()
