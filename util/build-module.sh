# Copyright 2018 Carbon Black Inc.  All rights reserved.
set -x
TOP_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )/.."

source ${BUILD_UTIL_DIR}/sh-utils/conan-utils.sh

# Expand env variables
function do_validate_env_step
{
    echo "Beginning do_validate_env_step..."
    BUILD_DIR=$(echo ${BUILD_DIR} | envsubst)
    BUILD_DIR=${BUILD_DIR//${DUB_SLSH}/${SLSH}}
    echo "--BUILD_DIR=${BUILD_DIR}"

    export PROJECT_VERSION=$(echo ${PROJECT_VERSION} | envsubst)
    echo "--PROJECT_VERSION=${PROJECT_VERSION}"

    export JOBS=$(echo "-j${JOBS}" | envsubst)
    echo "--JOBS=${JOBS}"

    export PLATFORM_BUILD=${BUILD_DIR}
    echo "--PLATFORM_BUILD=${PLATFORM_BUILD}"

    export COVERITY_BUILD_DIR=$(echo ${COVERITY_BUILD_DIR} | envsubst)
    echo "--COVERITY_BUILD_DIR=${COVERITY_BUILD_DIR}"

    export COVERAGE_DIR=${BUILD_DIR}/coverage
    echo "--COVERAGE_DIR=${COVERAGE_DIR}"

    export CONAN_PROFILE=$(echo ${CONAN_PROFILE} | envsubst)
    echo "--CONAN_PROFILE=${CONAN_PROFILE}"

    export SOURCE_VERSION=$(echo ${SOURCE_VERSION} | envsubst)
    export PACKAGE_VERSION=$PROJECT_VERSION
    echo "--PACKAGE_VERSION=${PACKAGE_VERSION}"
    export PACKAGE_MAJOR_VERSION=$(echo ${PROJECT_VERSION} | cut -d "." -f 1 )
    echo "--PACKAGE_MAJOR_VERSION=${PACKAGE_MAJOR_VERSION}"
    export PACKAGE_MINOR_VERSION=$(echo ${PROJECT_VERSION} | cut -d "." -f 2 )
    echo "--PACKAGE_MINOR_VERSION=${PACKAGE_MINOR_VERSION}"
    export PACKAGE_POINT_VERSION=$(echo ${PROJECT_VERSION} | cut -d "." -f 3 )
    echo "--PACKAGE_POINT_VERSION=${PACKAGE_POINT_VERSION}"
    export PACKAGE_DIR=$(echo ${PACKAGE_DIR} | envsubst)
    export PACKAGE_NAME=$(echo ${PACKAGE_NAME} | envsubst)
    export PACKAGE_CHANNEL=$(echo ${PACKAGE_CHANNEL} | envsubst)
    export PACKAGE_PATH=$(echo ${PACKAGE_PATH} | envsubst)
    export CONAN_PROFILE=$(echo ${CONAN_PROFILE} | envsubst)

    export PACKAGE_CHANNEL=$(echo ${PACKAGE_CHANNEL} | envsubst)
    echo "--PACKAGE_CHANNEL=${PACKAGE_CHANNEL}"

    if [ "$BUILD_VERBOSE" == "yes" ]; then
        export VERBOSE_OPT=VERBOSE=1
    fi

    if [[ $BUILD_TYPE == "debug" ]]; then
        CMAKE_BUILD_TYPE=Debug
    elif [[ $BUILD_TYPE == "release" ]]; then
        CMAKE_BUILD_TYPE=RelWithDebInfo
    elif [[ $BUILD_TYPE == "coverage" ]]; then
        CMAKE_BUILD_TYPE=Coverage
        export BUILD_COVERAGE=1
        export COVFILE=${TOP_DIR}/cbr.cov.dummy
        # Replace the compiler
        CMAKE_CXX_COMPILER="/opt/BullseyeCoverage/bin/covc -q -t!**/vendor/,!**/proto/ -i ${CMAKE_CXX_COMPILER}"
        CMAKE_C_COMPILER="/opt/BullseyeCoverage/bin/covc -q -t!**/vendor/,!**/proto/ -i ${CMAKE_C_COMPILER}"
    elif [[ $BUILD_TYPE == "veracode" ]]; then
        CMAKE_BUILD_TYPE=Veracode
    else
        echo >&2 "$0: INVALID BUILD TYPE $1"
        exit 1
    fi
    export CMAKE_BUILD_TYPE

    # If GCOV not set, default it to /usr/bin/gcov
    if [ -z "$GCOV" ]; then
        export GCOV=/usr/bin/gcov
    fi
    echo "Finished do_validate_env_step."
}

function do_prepare_step
{
    echo "Beginning do_prepare_step..."
    rm -rf ${BUILD_DIR}/*

    pushd ${TOP_DIR} &>/dev/null

    # Add git metadata to the build
    GIT_BRANCH="${GIT_BRANCH:-$(git rev-parse --abbrev-ref HEAD)}"
    GIT_COMMIT="${GIT_COMMIT:-$(git rev-parse HEAD)}"

    echo "  Building from $GIT_BRANCH @ $GIT_COMMIT"
    echo "$GIT_BRANCH" > ${BUILD_DIR}/branch.git.txt
    echo "$GIT_COMMIT" > ${BUILD_DIR}/revision.git.txt

    popd &>/dev/null
    echo "Finished do_prepare_step."
}

function build_kernel_event_collector_module
{
    echo "Building kernel event collector module..."

    echo "Done building kernel event collector module."
}

function tdd_build_kernel_event_collector_module
{
    echo "Building kernel event collector module under tdd..."

    echo "Done building kernel event collector module under tdd."
}

source ${BUILD_UTIL_DIR}/sh-utils/build-tdd.sh

function do_build_step
{
    echo "Doing build step for kernel module..."

    mkdir -p ${PLATFORM_BUILD}
    echo "--Created ${PLATFORM_BUILD}"
    local ORIGINAL_SOURCE=${TOP_DIR}
    echo "--ORIGINAL_SOURCE=${ORIGINAL_SOURCE}"
    local PLATFORM_SOURCE=${PLATFORM_BUILD}/project-src
    echo "--PLATFORM_SOURCE=${PLATFORM_SOURCE}"

    echo "--- Syncing folders"
#    echo "--Syncing ${PLATFORM_BUILD}/imports to ${TOP_DIR}/imports"
#    sync_directory ${PLATFORM_BUILD}/imports        ${TOP_DIR}/imports
#    echo "--Syncing ${PLATFORM_BUILD}/cpack to ${TOP_DIR}/cpack"
#    sync_directory ${PLATFORM_BUILD}/cpack          ${TOP_DIR}/cpack
    echo "--Syncing ${PLATFORM_SOURCE} to ${ORIGINAL_SOURCE}"
    sync_directory ${PLATFORM_SOURCE}               ${ORIGINAL_SOURCE}

    echo "-- /src contains"
    ls -l /src
    echo "-- /src/src contains"
    ls -l /src/src
    echo "-- /src/workspace contains"
    ls -l /src/workspace
    echo "-- /src/workspace/src contains"
    ls -l /src/workspace/src
    echo "-- /src/workspace/build contains"
    ls -l /src/workspace/build
    echo "-- /src/workspace/build/project-src contains"
    ls -l /src/workspace/build/project-src

        # Replace the version string
    find ${PLATFORM_SOURCE} -type f -iname conanfile.py -print0 | while IFS= read -r -d $'\0' file; do
        echo "--Applying replacements to ${file}..."
        apply_file_replacements $file
        echo "--Applied replacements to ${file}"
    done

    # Call the source method
    echo "--Calling conan source --source-folder ${PLATFORM_SOURCE} ${PLATFORM_SOURCE}..."
    conan source --source-folder ${PLATFORM_SOURCE} ${PLATFORM_SOURCE}
    echo "--Called conan source --source-folder ${PLATFORM_SOURCE} ${PLATFORM_SOURCE}."

    echo "# Building in ${BUILD_DIR}..."

    if [ "$PACKAGE_OPTIONS" != "None" ]; then
        O=$PACKAGE_OPTIONS
    fi
    PACKAGE_OPTIONS=""
    for i in $(echo $O | sed "s/,/ /g"); do
        PACKAGE_OPTIONS="$PACKAGE_OPTIONS -o $i"
    done
    export PACKAGE_OPTIONS=$(echo ${PACKAGE_OPTIONS} | envsubst)

    local CONAN_UPDATE="--update"

    if [ "${PREFER_LOCAL_CACHE}" = "yes" ]; then
        CONAN_UPDATE=""
    fi

    if [ "${EXPORT_RECIPE_ONLY}" = "yes" ]; then
        flock ${BUILD_DIR} \
              ${CMD_PREFIX} conan export \
              ${PLATFORM_BUILD} \
              ${PACKAGE_NAME}
        # I need to trick some of the TDD logic to think we are working correctly
        touch ${PLATFORM_BUILD}/conanbuildinfo.txt
    else
        echo "---taking else route"
        # Install any package dependencies
        echo "---FAST_BUILD=${FAST_BUILD}"
        echo "---BUILD_DIR=${BUILD_DIR}"
        echo "---CMD_PREFIX=${CMD_PREFIX}"
        echo "---CONAN_PROFILE=${CONAN_PROFILE}"
        echo "---PACKAGE_OPTIONS=${PACKAGE_OPTIONS}"
        echo "---PLATFORM_BUILD=${PLATFORM_BUILD}"
        if [ $FAST_BUILD -ne 1 ]; then
          # flock /src/workspace/kernel_event_collector_module//build conan install
          # -pr /src/build-util/conan-profiles/redhat6-gcc48-relwithdebinfo
          # --update
          # -o module_name=event_collector
          # --install-folder /src/workspace/kernel_event_collector_module//build/redhat6.1
          # /src/workspace/kernel_event_collector_module//build/redhat6.1

          # flock /src/workspace//build conan install
          # -pr '/src/build-util/conan-profiles/${CONAN_PROFILE_NAME}'
          # --update module_name=event_collector
          # --install-folder /src/workspace//build
          # /src/workspace//build
          echo "---Calling conan install"
            flock ${BUILD_DIR} \
                  ${CMD_PREFIX} conan install -pr ${CONAN_PROFILE} \
                                ${CONAN_UPDATE} \
                                ${PACKAGE_OPTIONS} \
                                --install-folder ${PLATFORM_SOURCE} \
                                ${PLATFORM_SOURCE}
        fi

        # Build the package
        ${CMD_PREFIX} conan build --build-folder ${PLATFORM_SOURCE} ${PLATFORM_SOURCE}
        RET=$?
        if [[ $RET = 0 && "${SKIP_PACKAGING}" != "True" ]]; then
            # Export the package into the local cache
            echo ""
            echo "# Packaging..."
            # + flock /src/workspace/kernel_event_collector_module//build conan export-pkg
            # -f
            # --build-folder /src/workspace/kernel_event_collector_module//build/redhat6.1
            # /src/workspace/kernel_event_collector_module//build/redhat6.1
            # dev/testing

            # flock /src/workspace//build conan export-pkg
            # -f
            # --build-folder /src/workspace//build/project-src
            # /src/workspace//build
            # /src/workspace//build/project-src
            flock ${BUILD_DIR} \
                  ${CMD_PREFIX} conan export-pkg -f \
                  --build-folder ${PLATFORM_SOURCE} \
                  ${PLATFORM_SOURCE} \
                  ${PACKAGE_CHANNEL}

            if [ "$ENABLE_COVERAGE" = "yes" ]
            then
                do_test_coverage
            else
                echo "Coverage Not Enabled"
            fi
        fi
    fi

    echo "Done doing build step for kernel module."
}

function do_package_step
{
    echo "Doing package step for kernel module..."

    echo "Done doing package step for kernel module."
}

function do_package_fail_step
{
    echo "Doing package fail step for kernel module..."

    echo "Done doing package fail step for kernel module."
}
