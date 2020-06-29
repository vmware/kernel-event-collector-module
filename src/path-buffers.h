#pragma once

#include "process-context.h"


bool path_buffers_init(ProcessContext * context);
void path_buffers_shutdown(ProcessContext *context);
char *get_path_buffer(ProcessContext *context);
void put_path_buffer(char *buffer);
