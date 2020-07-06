# Copyright 2018 Carbon Black Inc.  All rights reserved.
TOP_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )/.."

source ${BUILD_UTIL_DIR}/sh-utils/conan-utils.sh

# Expand env variables
function do_validate_env_step
{
    echo "Beginning do_validate_env_step..."
    BUILD_DIR=$(echo ${BUILD_DIR} | envsubst)
    BUILD_DIR=${BUILD_DIR//${DUB_SLSH}/${SLSH}}

    export PROJECT_VERSION=$(echo ${PROJECT_VERSION} | envsubst)
    export JOBS=$(echo "-j${JOBS}" | envsubst)

    export PLATFORM_BUILD=${BUILD_DIR}/${SERVICE}

    if [ "$BUILD_VERBOSE" == "yes" ]; then
        export VERBOSE_OPT=VERBOSE=1
    fi

    if [[ $BUILD_TYPE == "debug" ]]; then
        CMAKE_BUILD_TYPE=Debug
    elif [[ $BUILD_TYPE == "release" ]]; then
        CMAKE_BUILD_TYPE=RelWithDebInfo
    else
        echo >&2 "$0: INVALID BUILD TYPE $1"
        exit 1
    fi
    export CMAKE_BUILD_TYPE

    export COVERITY_BUILD_DIR=$(echo ${COVERITY_BUILD_DIR} | envsubst)

    export CONAN_PROFILE=$(echo ${CONAN_PROFILE} | envsubst)

    export SOURCE_VERSION=$(echo ${SOURCE_VERSION} | envsubst)

    export PACKAGE_VERSION=$PROJECT_VERSION
    export PACKAGE_MAJOR_VERSION=$(echo ${PROJECT_VERSION} | cut -d "." -f 1 )
    export PACKAGE_MINOR_VERSION=$(echo ${PROJECT_VERSION} | cut -d "." -f 2 )
    export PACKAGE_POINT_VERSION=$(echo ${PROJECT_VERSION} | cut -d "." -f 3 )
    export PACKAGE_DIR=$(echo ${PACKAGE_DIR} | envsubst)
    export PACKAGE_NAME=$(echo ${PACKAGE_NAME} | envsubst)
    export PACKAGE_CHANNEL=$(echo ${PACKAGE_CHANNEL} | envsubst)
    export PACKAGE_PATH=$(echo ${PACKAGE_PATH} | envsubst)

    echo "Finished do_validate_env_step."
}

function do_prepare_step
{
    echo "Beginning do_prepare_step..."
    rm -rf ${BUILD_DIR}/*

    echo "KERNEL_EVENT_COLLECTOR_MODULE_VERSION: ${PACKAGE_NAME}" > ${BUILD_DIR}/manifest

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

#funcion do_gather_dependencies
#{
#    echo "Starting do_gather_dependencies..."
#
#    echo "Finished do_gather_dependencies."
#}

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

    echo "--Creating directory: ${PLATFORM_BUILD}"
    mkdir -p ${PLATFORM_BUILD}

    echo "--Creating a project src dir to avoid recursive syncs with build"
    local project_src_dir="${PLATFORM_BUILD}/project-src"
    mkdir -p "${project_src_dir}"

    echo "--Copying all build files in ${TOP_DIR} to ${project_src_dir}"
    find ${TOP_DIR} -maxdepth 1 -type f -exec cp {} ${project_src_dir} \;
    cp -r ${TOP_DIR}/include ${project_src_dir}
    cp -r ${TOP_DIR}/src ${project_src_dir}

    local platform_src=${PLATFORM_BUILD}
    sync_directory ${platform_src} ${project_src_dir}

        # Replace the version string
    echo "--Beginning find for conanfile..."
    find ${PLATFORM_BUILD} -type f -iname conanfile.py -print0 | while IFS= read -r -d $'\0' file; do
        echo "--Applying replacements to ${file}..."
        apply_file_replacements $file
        echo "--Applied replacements to ${file}"
    done
    echo "--Finished find for conanfile."

    # Call the source method
    echo "--Calling conan source --source-folder ${PLATFORM_BUILD} ${PLATFORM_BUILD}..."
    conan source --source-folder ${PLATFORM_BUILD} ${PLATFORM_BUILD}
    echo "--Called conan source --source-folder ${PLATFORM_BUILD} ${PLATFORM_BUILD}."

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
        flock ${BUILD_DIR} ${CMD_PREFIX} conan export ${PLATFORM_BUILD} ${PACKAGE_NAME}
        # I need to trick some of the TDD logic to think we are working correctly
        touch ${PLATFORM_BUILD}/conanbuildinfo.txt
    else
        if [ $FAST_BUILD -ne 1 ]; then
            flock ${BUILD_DIR} ${CMD_PREFIX} conan install \
                -pr ${CONAN_PROFILE} \
                ${CONAN_UPDATE} \
                ${PACKAGE_OPTIONS} \
                --install-folder ${PLATFORM_BUILD} \
                ${PLATFORM_BUILD}
        fi

        # Build the package
        ${CMD_PREFIX} conan build --build-folder ${PLATFORM_BUILD} ${PLATFORM_BUILD}
        RET=$?
        if [[ $RET = 0 && "${SKIP_PACKAGING}" != "True" ]]; then
            # Export the package into the local cache
            echo "# Packaging..."
            flock ${BUILD_DIR} ${CMD_PREFIX} conan export-pkg -f \
                  --build-folder ${PLATFORM_BUILD} \
                  ${PLATFORM_BUILD} \
                  ${PACKAGE_CHANNEL}

            if [ "$ENABLE_COVERAGE" = "yes" ]
            then
                echo "Coverage is not currently supported for this project"
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
