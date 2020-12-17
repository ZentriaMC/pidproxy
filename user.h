#pragma once

#include <sys/types.h>

int resolve_uid_gid(const char *name, uid_t *uid, gid_t *gid,
                    size_t *supplementary_group_n,
                    gid_t **supplementary_groups);

int resolve_gid(const char *name, gid_t *gid);
