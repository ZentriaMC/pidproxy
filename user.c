#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include "user.h"

int resolve_uid_gid(const char *name, uid_t *uid, gid_t *gid,
                    size_t *supplementary_group_n,
                    gid_t **supplementary_groups) {
  int is_number = 1;
  for (size_t i = 0; i < strnlen(name, 32); i++) {
    if (!isdigit(name[i])) {
      is_number = 0;
      break;
    }
  }

  struct passwd pwd;
  struct passwd *result;
  int r;
  char *buf = NULL;
  size_t bufsz;
  int sgroup_n = 8;
  gid_t *sgroups = NULL;
  long s2;
  if ((s2 = sysconf(_SC_GETPW_R_SIZE_MAX)) == -1) {
    bufsz = 2 << 13;
  } else {
    bufsz = s2;
  }
  if ((buf = malloc(bufsz)) == NULL) {
    perror("malloc");
    return -1;
  };

  if (is_number) {
    // Convert to integer first
    uid_t provided_uid = strtoul(name, NULL, 10);
    if (errno != 0) {
      perror("strtoul");
      goto err;
    }

    r = getpwuid_r(provided_uid, &pwd, buf, bufsz, &result);
  } else {
    r = getpwnam_r(name, &pwd, buf, bufsz, &result);
  }

  if (result == NULL) {
    if (r != 0) {
      perror(is_number ? "getpwuid_r" : "getpwnam_r");
    }
    goto err;
  }

  *uid = result->pw_uid;
  *gid = result->pw_gid;

  // Grab supplementary groups
  sgroups = malloc(sizeof(gid_t) * sgroup_n);
  if (sgroups == NULL) {
    perror("malloc");
    goto err;
  }

  while (getgrouplist(result->pw_name, result->pw_gid, sgroups, &sgroup_n) < 0) {
    gid_t *n_sgroups;
    if ((n_sgroups = realloc(sgroups, sizeof(gid_t) * sgroup_n)) == NULL) {
      perror("realloc");
      goto err;
    };
    sgroups = n_sgroups;
  }

  if (sgroup_n == 0) {
    free(sgroups);
    sgroups = NULL;
  }

  *supplementary_group_n = sgroup_n;
  *supplementary_groups = sgroups;

  if (buf != NULL) {
    free(buf);
  }
  return 0;

 err:
  if (sgroups != NULL) {
    free(sgroups);
  }
  if (buf != NULL) {
    free(buf);
  }
  return -1;
}

int resolve_gid(const char *name, gid_t *gid) {
  int is_number = 1;
  for (size_t i = 0; i < strnlen(name, 32); i++) {
    if (!isdigit(name[i])) {
      is_number = 0;
      break;
    }
  }

  struct group grp;
  struct group *result;
  int r;
  char *buf;
  size_t bufsz;
  long s2;
  if ((s2 = sysconf(_SC_GETGR_R_SIZE_MAX)) == -1) {
    bufsz = 2 << 13;
  } else {
    bufsz = s2;
  }
  if ((buf = malloc(bufsz)) == NULL) {
    perror("malloc");
    return -1;
  };

  if (is_number) {
    // Convert to integer first
    uid_t provided_gid = strtoul(name, NULL, 10);
    if (errno != 0) {
      perror("strtoul");
      goto err;
    }

    r = getgrgid_r(provided_gid, &grp, buf, bufsz, &result);
  } else {
    r = getgrnam_r(name, &grp, buf, bufsz, &result);
  }

  if (result == NULL) {
    if (r != 0) {
      perror(is_number ? "getgrgid_r" : "getgrnam_r");
    }
    goto err;
  }

  *gid = result->gr_gid;

  free(buf);
  return 0;

 err:
  free(buf);
  return -1;
}
