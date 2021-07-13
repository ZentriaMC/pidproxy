/*
 * This file is part of pidproxy.
 * Copyright (c) 2020-2021 Zentria OÜ.
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

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>

#include "user.h"

#define MAX_EVENTS 5
#define PIDFILE_INITIAL_WAIT_TIME 2
#define PIDFILE_MAX_WAIT_TIME 10

#if !defined(SYS_pidfd_open) && defined(__x86_64__) // just to be sure.
#  define SYS_pidfd_open 434
#endif

#ifdef __SIGRTMIN
#  define P_SIG_MAX (__SIGRTMIN-1)
#else
#  define P_SIG_MAX 31 // XXX: not future proof
#endif

#ifndef PATH_MAX
#  define PATH_MAX 4096
#endif

#define USAGE_TEXT \
"-h\t\tShows this help text\n"\
"-g\t\tWhether to kill whole process group (defaults to no)\n"\
"-r <from=to>\tPass received signal `from` to child as `to`. Can be specified multiple times\n"\
"-t\t\tWhether to allow running from tty as a root. Used to prevent exploits using TIOCSTI ioctl\n"\
"-U <uid>\tWhat UID to run the child process as\n"\
"-G <gid>\tWhat GID to run the child process as (default: main group of user specified by -U flag, otherwise current gid)\n"\
"-E <path-to-program>\tAn external program to run after monitored process exits.\n"

static int w_pidfd_open(pid_t pid, unsigned int flags) {
  return syscall(SYS_pidfd_open, pid, flags);
}

static int w_pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags) {
  return syscall(SYS_pidfd_send_signal, pidfd, sig, info, flags);
}

extern char **environ;

static int add_pollable_fd(int efd, int fd) {
  if (fd == -1) {
    return -1;
  }

  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = fd;

  if (epoll_ctl(efd, EPOLL_CTL_ADD, ev.data.fd, &ev) == -1) {
    goto err;
  }

  return fd;

 err:
  close(fd);
  return -2;
}

#define should_try_again(r) ((r) == -1 && (errno) == EINTR)

static int pidfd_working = 1;

static int add_pollable_pid(int efd, pid_t pid) {
  if (!pidfd_working) {
    return -1;
  }

  int pidfd;
  if ((pidfd = w_pidfd_open(pid, 0)) == -1) {
    int err = errno;
    if (err == ENOSYS) {
      fprintf(stderr, "pidfd_open syscall is not supported, falling back to polling\n");
      pidfd_working = 0;
    } else if (err == EPERM) {
      fprintf(stderr, "seems like pidfd_open syscall does not work, falling back to polling\n");
      pidfd_working = 0;
    }
    errno = err;
    return -1;
  }

  return add_pollable_fd(efd, pidfd);
}

static int watch_target_process(int epfd, const char *pidfile_name,
                                pid_t *target_pid_ptr, int *target_pid_fd_ptr) {
  int r;
  FILE* pid_file = fopen(pidfile_name, "r");
  if (!pid_file) {
    fprintf(stderr, "failed to open pidfile '%s': %s\n", pidfile_name, strerror(errno));
    goto end;
  }

  pid_t target_pid = -1;

  // Read PID file from the file
  do { r = fscanf(pid_file, "%d", &target_pid); } while (should_try_again(r));
  if (target_pid <= 0) {
    if (feof(pid_file)) {
      fprintf(stderr, "pid file '%s' was empty\n", pidfile_name);
    } else if (target_pid == 0) {
      fprintf(stderr, "could not find a pid from file '%s'\n", pidfile_name);
    } else if (target_pid == -1) {
      perror("fscanf");
    }
    fclose(pid_file);
    goto end;
  }

  fclose(pid_file);
  *target_pid_ptr = target_pid;

  if (!pidfd_working) {
    *target_pid_fd_ptr = -1;
    return 0;
  }

  // Open pidfd. This is not fatal, however we won't know when target process exits.
  if ((r = add_pollable_pid(epfd, target_pid)) < 0) {
    if (errno == ESRCH) {
      // Process has exited
      return -2;
    }
    fprintf(stderr, "failed to watch target process (%s error): %s\n", r == -1 ? "pidfd_open" : "epoll_ctl", strerror(errno));
  } else {
    *target_pid_fd_ptr = r;
  }

  return 0;

 end:
  return -1;
}

static int signal_rewrites[P_SIG_MAX + 1] = {[0 ... P_SIG_MAX] = -1};

static int parse_signal_rewrite(const char *arg) {
  int orig, repl;
  if (sscanf(arg, "%d=%d", &orig, &repl) == 2) {
    if (orig < 1 || orig > P_SIG_MAX) {
      goto end;
    }
    if (repl < 1 || repl > P_SIG_MAX) {
      goto end;
    }

    signal_rewrites[orig] = repl;
    return 0;
  }
 end:
  return -1;
}

static uint64_t timer_cycles = 0;
static uint64_t direct_child_exited_at = 0;
static unsigned int exit_signals_caught = 0;

static int print_help(const char *name, int code) {
  fprintf(stderr, "USAGE: %s [options] <path to pid file> <argv>\n", name);
  fprintf(stderr, "\n" USAGE_TEXT "\n");
  return code;
}

int main(int argc, char **argv) {
  int r, ret = 0, direct_child_fd = -1, target_pid_fd = -1;
  int kill_process_group = 0;
  int allow_tty = 0;
  pid_t target_pid = -1;

  char *target_uid_value = NULL;
  char *target_gid_value = NULL;
  uid_t target_uid = 0;
  gid_t target_gid = 0;
  size_t supplementary_group_n = 0;
  gid_t *supplementary_groups = NULL;

  char *exit_hook = NULL;

  struct epoll_event events[MAX_EVENTS];
  struct signalfd_siginfo last_siginfo;

  // Parse optional arguments
  while ((r = getopt(argc, argv, "ghr:tU:G:E:")) != -1) {
    switch (r) {
    case 'g':
      kill_process_group = 1;
      break;
    case 'h':
      return print_help(argv[0], 0);
    case 'r':
      if (parse_signal_rewrite(optarg) == -1) {
        fprintf(stderr, "failed to parse signal rewrite: '%s'\n", optarg);
        return 1;
      }
      break;
    case 't':
      allow_tty = 1;
      break;
    case 'U':
      if (getuid() != 0) {
        fprintf(stderr, "cannot setuid when current uid is not 0\n");
        return 1;
      }

      if (target_uid_value != NULL) {
        free(target_uid_value);
      }
      target_uid_value = strndup(optarg, 256-1);

      break;
    case 'G': {
      if (getuid() != 0) {
        fprintf(stderr, "cannot setgid when current uid is not 0\n");
        return 1;
      }

      if (target_gid_value != NULL) {
        free(target_gid_value);
      }
      target_gid_value = strndup(optarg, 256-1);

      break;
    }
    case 'E':
      exit_hook = strndup(optarg, PATH_MAX-1);

      break;
    default:
      return 1;
    }
  }

  if ((argc - optind + 1) < 3) {
    return print_help(argv[0], 1);
  }

  if (getuid() == 0 && !allow_tty && isatty(STDIN_FILENO) == 1) {
    fprintf(stderr, "running in tty is not allowed as a root. use `-t` to bypass if you're sure what you are doing.\n");
    return 1;
  }

  if (getuid() == 0 && target_gid_value != NULL && resolve_gid(target_gid_value, &target_gid) < 0) {
    fprintf(stderr, "failed to resolve gid for '%s'\n", optarg);
    return 1;
  }

  if (getuid() == 0 && target_uid_value != NULL && resolve_uid_gid(target_uid_value, &target_uid, &target_gid, &supplementary_group_n, &supplementary_groups) < 0) {
    fprintf(stderr, "failed to resolve uid for '%s'\n", optarg);
    return 1;
  }

  if (target_uid_value != NULL) {
    free(target_uid_value);
    target_uid_value = NULL;
  }

  if (target_gid_value != NULL) {
    free(target_gid_value);
    target_gid_value = NULL;
  }

  char *pidfile_name = argv[optind];
  int child_argv_start = optind + 1;

  // Set up epoll
  int epollfd;
  if ((epollfd = epoll_create1(EPOLL_CLOEXEC)) == -1) {
    perror("epoll_create1");
    return 1;
  }

  // Ignore SIGCHLD
  signal(SIGCHLD, SIG_IGN);

  // Set up signal mask and signalfd
  sigset_t mask;
  sigset_t old_mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGHUP);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGQUIT);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGUSR1);
  sigaddset(&mask, SIGUSR2);

  if (sigprocmask(SIG_BLOCK, &mask, &old_mask) == -1) {
    perror("sigprocmask");
    return 1;
  }

  int sigfd;
  if ((sigfd = add_pollable_fd(epollfd, signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC))) < 0) {
    fprintf(stderr, "failed to set up signalfd (%s error): %s\n", sigfd == -1 ? "signalfd" : "epoll_ctl", strerror(errno));
    return 1;
  }

  // Set up timer and make it tick after every 1 second
  int timerfd;
  if ((timerfd = add_pollable_fd(epollfd, timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK))) < 0) {
    fprintf(stderr, "failed to set up timerfd (%s error): %s\n", timerfd == -1 ? "timerfd_create" : "epoll_ctl", strerror(errno));
    return 1;
  }

  struct itimerspec timer_spec = { 0 };
  timer_spec.it_value.tv_sec = PIDFILE_INITIAL_WAIT_TIME;
  timer_spec.it_interval.tv_sec = 1;

  if (timerfd_settime(timerfd, 0, &timer_spec, NULL) == -1) {
    perror("timerfd_settime");
    return 1;
  }

  // Spawn daemonizing program
  {
    sigset_t all_signals;
    sigfillset(&all_signals);

    pid_t direct_child;
    if ((direct_child = fork()) == -1) {
      perror("fork");
      return 1;
    } else if (direct_child == 0) {
      // Unblock all signals for child
      sigprocmask(SIG_UNBLOCK, &all_signals, NULL);

      if (target_gid != 0) {
        if (setgid(target_gid) < 0) {
          perror("setgid");
          _exit(1);
        }

        if (supplementary_group_n > 0 && setgroups(supplementary_group_n, supplementary_groups) < 0) {
          perror("setgroups");
          _exit(1);
        }
      }

      if (target_uid != 0) {
        if (setuid(target_uid) < 0) {
          perror("setuid");
          _exit(1);
        }

        if (setuid(0) == 0 || seteuid(0) == 0) {
          fprintf(stderr, "could not drop root privileges\n");
          return -1;
        }
      }

      if (execvp(argv[child_argv_start], &argv[child_argv_start]) == -1) {
        perror("execvp");
      }
      _exit(1);
    }

    if (supplementary_group_n > 0 && supplementary_groups != NULL) {
      free(supplementary_groups);
    }

    if ((direct_child_fd = add_pollable_pid(epollfd, direct_child)) < 0) {
      if (errno != ESRCH) {
        fprintf(stderr, "failed to watch for direct child exit (%s error): %s\n", direct_child_fd == -1 ? "pidfd_open" : "epoll_ctl", strerror(errno));
      }
    }
  }

  // Clear argv
  for (int i = child_argv_start; i < argc; i++) {
    bzero(argv[i], strlen(argv[i]));
  }

  // Start polling
  int evts;
  while (1) {
    do { evts = epoll_wait(epollfd, events, MAX_EVENTS, -1); } while (should_try_again(evts));
    if (evts == -1) {
      perror("epoll_wait");
      return 1;
    }

    // Process events
    for (int i = 0; i < evts; i++) {
      struct epoll_event evt = events[i];
      int fd = evt.data.fd;
      if (fd == direct_child_fd) {
        // *** Direct child exit

        direct_child_fd = -1;
        close(direct_child_fd);
      } else if (fd == timerfd) {
        // *** Timer
        uint64_t expires;
        do { r = read(timerfd, &expires, sizeof(uint64_t)); } while (should_try_again(r));
        if (r == -1) {
          fprintf(stderr, "failed to read timerfd: %s\n", strerror(errno));
          continue;
        }
        timer_cycles++;

        if (target_pid == -1 && direct_child_fd == -1) {
          if (direct_child_exited_at == 0) {
            direct_child_exited_at = timer_cycles;
          }

          if ((timer_cycles - direct_child_exited_at) > PIDFILE_MAX_WAIT_TIME) {
            fprintf(stderr, "target process did not appear after waiting for %d seconds\n", PIDFILE_MAX_WAIT_TIME);
            ret = 1;
            goto exit;
          }

          // Try reading pidfile
          if (watch_target_process(epollfd, pidfile_name, &target_pid, &target_pid_fd) == -2) {
            fprintf(stderr, "process has died, quitting\n");
            goto exit;
          }
        }

        if (target_pid != -1) {
          if (direct_child_fd == -1) {
            // Need to poll the PID
            if (kill(target_pid, 0) == -1) {
              if (errno == ESRCH) {
                fprintf(stderr, "process has died, quitting\n");
                goto exit;
              }
              perror("kill");
            }
          } else {
            // We don't need timer anymore.
            close(timerfd);
            timerfd = -1;
          }
        }
      } else if (fd == sigfd) {
        // *** Signal handling
        bzero(&last_siginfo, sizeof(struct signalfd_siginfo));
        if (read(fd, &last_siginfo, sizeof(struct signalfd_siginfo)) == -1) {
          perror("read");
          continue;
        }

        int sig = last_siginfo.ssi_signo;
        if ((r = signal_rewrites[last_siginfo.ssi_signo]) != -1) {
          fprintf(stderr, "got signal %d (translating to %d)\n", sig, r);
          sig = r;
        } else {
          fprintf(stderr, "got signal %d\n", sig);
        }

        // Try reading pidfile
        if (target_pid == -1) {
          if (watch_target_process(epollfd, pidfile_name, &target_pid, &target_pid_fd) == -2) {
            fprintf(stderr, "process has died, quitting\n");
            goto exit;
          }
        }

        if (target_pid == -1) {
          fprintf(stderr, "child does not seem to be available yet\n");
          if (sig == SIGINT || sig == SIGQUIT || sig == SIGTERM) {
            exit_signals_caught++;
          }

          if (exit_signals_caught > 2) {
            fprintf(stderr, "got exit signal 3 times while child was not present, exiting\n");
            ret = 1;
            goto exit;
          }
        } else {
          // TODO: remember to keep eye on `pidfd_send_signal` changes, since it does not support killing a process group.
          int method_used = kill_process_group || target_pid_fd == -1;
          if ((method_used ? kill(kill_process_group ? -target_pid : target_pid, sig) : w_pidfd_send_signal(target_pid_fd, sig, NULL, 0)) == -1) {
            if (errno == ESRCH) {
              fprintf(stderr, "process has died, quitting\n");
              goto exit;
            }
            perror(method_used ? "kill" : "pidfd_send_signal");
          }
        }
      } else if (fd == target_pid_fd) {
        // *** Target process
        fprintf(stderr, "monitored pid %d exited, quitting\n", target_pid);

        close(target_pid_fd);
        target_pid = -1;
        target_pid_fd = -1;

        goto exit;
      }
    }
  }

exit:
  // Restore old signal mask
  if (sigprocmask(SIG_BLOCK, &old_mask, NULL) == -1) {
    perror("sigprocmask");
    // XXX: would be silly to fail fatally here... just hope for the best
  }

  signal(SIGCHLD, SIG_DFL);

  // Run exit hook, if set
  if (exit_hook != NULL) {
    fprintf(stderr, "running exit hook '%s'\n", exit_hook);

    char *const eh_argv[] = {
      exit_hook,
      NULL
    };

    // Populate envvars
    size_t env_count = 0;
    for (char **e = environ; *e; e++) {
      env_count++;
    }

    size_t eh_envp_idx = 0;
    char **eh_envp = malloc((env_count + 4) * sizeof(char *));
    for (char **e = environ; *e; e++) {
      eh_envp[eh_envp_idx++] = strdup(*e);
    }

    char pidfile_abs_path[PATH_MAX];
    int has_realpath = 0;
    if (!(has_realpath = !!realpath(pidfile_name, pidfile_abs_path))) { // XXX: gross
      perror("realpath");
    }

#define add_env(sz, fmt, ...) snprintf((eh_envp[eh_envp_idx++] = malloc((sizeof((fmt)) + (sz)))), (sizeof((fmt)) + (sz)) - 1, (fmt), __VA_ARGS__)
    add_env(PATH_MAX, "PIDPROXY_PID_FILE=%s", has_realpath ? pidfile_abs_path : pidfile_name);
    add_env(11, "PIDPROXY_EXIT_CODE=%d", ret);
    add_env(11, "PIDPROXY_PID=%d", getpid());
    add_env(11, "PIDPROXY_CHILD_EXIT_CODE=%d", 0); // TODO: need to actually find a way to get the child exit status
    add_env(11, "PIDPROXY_CHILD_KILL_SIGNAL=%d", 0); // TODO: ^
#undef add_env

    pid_t eh_child = fork();
    if (eh_child == -1) {
      perror("fork");
    } else if (eh_child == 0) {
      // Execute the hook
      if (execve(eh_argv[0], eh_argv, (char *const *) eh_envp) < 0) {
        perror("execve");
        _exit(1);
      }
    } else {
      // Wait for the child to exit
      int status = 0;
      do { r = waitpid(eh_child, &status, WEXITED); } while (should_try_again(r));
      if (r < 0) {
        perror("waitpid");
      } else if (WIFEXITED(status)) {
        fprintf(stderr, "exit hook exited (code=%d)\n", WEXITSTATUS(status));
      } else if (WIFSIGNALED(status)) {
        fprintf(stderr, "exit hook killed (signal=%d)\n", WTERMSIG(status));
      }
    }

    // Free envvars
    for (char **e = eh_envp; *e; e++) {
      free(*e);
    }

    free(exit_hook);
  }

  return ret;
}
