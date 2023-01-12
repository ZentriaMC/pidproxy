/*
 * This file is part of pidproxy.
 * Copyright (c) 2020-2023 Zentria OÜ.
 *
 * pidproxy is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * pidproxy is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pidproxy. If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <sys/types.h>

int resolve_uid_gid(const char *name, uid_t *uid, gid_t *gid,
                    size_t *supplementary_group_n,
                    gid_t **supplementary_groups);

int resolve_gid(const char *name, gid_t *gid);
