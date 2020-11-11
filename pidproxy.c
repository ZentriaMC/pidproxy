#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>

#define MAX_EVENTS 4
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

inline int w_pidfd_open(pid_t pid, unsigned int flags) {
  return syscall(SYS_pidfd_open, pid, flags);
}

inline int w_pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags) {
  return syscall(SYS_pidfd_send_signal, pidfd, sig, info, flags);
}

static int add_pollable_fd(int efd, int fd) {
  struct epoll_event ev;
  ev.events = EPOLLIN;
  ev.data.fd = fd;

  return epoll_ctl(efd, EPOLL_CTL_ADD, ev.data.fd, &ev);
}

inline int remove_pollable_fd(int efd, int fd) {
  return epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
}

static int add_pollable_pid(int efd, pid_t pid) {
  int pidfd = w_pidfd_open(pid, 0);
  if (pidfd == -1) {
    return -1;
  }

  if (add_pollable_fd(efd, pidfd) == -1) {
    goto err;
  }

  return pidfd;
 err:
  close(pidfd);
  return -1;
 }

static pid_t read_pidfile(const char *pidfile_name) {
  int r = -1;
  pid_t target_pid = -1;
  FILE* pid_file = fopen(pidfile_name, "r");
  if (!pid_file) {
    fprintf(stderr, "failed to open pidfile '%s': %s\n", pidfile_name, strerror(errno));
    goto end;
  }

  do {
    r = fscanf(pid_file, "%d", &target_pid);
  } while (r == -1 && errno == EINTR);

  r = target_pid;
  fclose(pid_file);

 end:
  return r;
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

static uint32_t timer_cycles = 0;

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "USAGE: %s [options] <path to pid file> <argv>\n", argv[0]);
    return 1;
  }

  int child_argv_start;
  int r, evts, epollfd, sigfd, timerfd, target_pid_fd;
  pid_t target_pid = -1;
  char *pidfile_name;
  struct epoll_event events[MAX_EVENTS];
  struct signalfd_siginfo last_siginfo;

  // Parse optional arguments
  while ((r = getopt(argc, argv, "r:")) != -1) {
    switch (r) {
    case 'r':
      if (parse_signal_rewrite(optarg) == -1) {
        fprintf(stderr, "failed to parse signal rewrite: '%s'\n", optarg);
        return 1;
      }
      break;
    default:
      return 1;
    }
  }
  pidfile_name = argv[optind];
  child_argv_start = optind + 1;

  // Set up epoll
  if ((epollfd = epoll_create1(EPOLL_CLOEXEC)) == -1) {
    perror("epoll_create1");
    return 1;
  }

  // Ignore SIGCHLD
  signal(SIGCHLD, SIG_IGN);

  // Set up signal mask and signalfd
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGHUP);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGQUIT);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGUSR1);
  sigaddset(&mask, SIGUSR2);

  if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
    perror("sigprocmask");
    return 1;
  }

  if ((sigfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC)) == -1) {
    perror("signalfd");
    return 1;
  }

  if (add_pollable_fd(epollfd, sigfd) == -1) {
    perror("epoll_ctl");
    return 1;
  }

  // Set up timer and make it tick after every 1 second
  if ((timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK)) == -1) {
    perror("timerfd_create");
    return 1;
  }

  struct itimerspec timer_spec = { 0 };
  timer_spec.it_value.tv_sec = PIDFILE_INITIAL_WAIT_TIME;
  timer_spec.it_interval.tv_sec = 1;

  if (timerfd_settime(timerfd, 0, &timer_spec, NULL) == -1) {
    perror("timerfd_settime");
    return 1;
  }

  if (add_pollable_fd(epollfd, timerfd) == -1) {
    perror("epoll_ctl");
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

      if (execvp(argv[child_argv_start], &argv[child_argv_start]) == -1) {
        perror("execvp");
      }
      _exit(1);
    }
  }

  // Clear argv
  for (int i = child_argv_start; i < argc; i++) {
    memset(argv[i], 0, strlen(argv[i]));
  }

  // Start polling
  while (1) {
    if ((evts = epoll_wait(epollfd, events, MAX_EVENTS, -1)) == -1) {
      if (errno == EAGAIN) {
        continue;
      }
      perror("epoll_wait");
    }

    // Process events
    for (int i = 0; i < evts; i++) {
      struct epoll_event evt = events[i];
      int fd = evt.data.fd;
      if (fd == timerfd) {
        // *** Timer
        uint64_t _dummy;
        r = read(timerfd, &_dummy, sizeof(uint64_t));

        timer_cycles++;

        if (timer_cycles > PIDFILE_MAX_WAIT_TIME) {
          fprintf(stderr, "target process did not appear after waiting for %d seconds\n", PIDFILE_MAX_WAIT_TIME);
          return 1;
        } else if (target_pid == -1) {
          if ((r = read_pidfile(pidfile_name)) != -1) {
            target_pid = r;

            // Open pidfd and register it with epoll
            if ((target_pid_fd = add_pollable_pid(epollfd, target_pid)) == -1) {
              if (errno == ESRCH) {
                fprintf(stderr, "process has died, quitting\n");
                return 0;
              }
              perror("pidfd_open");
            }

            // Close timer
            if (remove_pollable_fd(epollfd, fd) == -1) {
              perror("epoll_ctl (failed to remove timer)");
            };
          }
        }

        if (target_pid != -1) {
          // We don't need timer anymore.
          close(timerfd);
          timerfd = -1;
        }
      } else if (fd == sigfd) {
        // *** Signal handling
        memset(&last_siginfo, 0, sizeof(struct signalfd_siginfo));
        if (read(fd, &last_siginfo, sizeof(struct signalfd_siginfo)) == -1) {
          perror("read");
          continue;
        }

        int sig = signal_rewrites[last_siginfo.ssi_signo];
        if (sig == -1) {
          sig = last_siginfo.ssi_signo;
        }
        fprintf(stderr, "got signal %d (translating to %d)\n", last_siginfo.ssi_signo, sig);

        if (target_pid == -1) {
          // Load pid immediately
          if ((r = read_pidfile(pidfile_name)) != -1) {
            target_pid = r;
          }

          if (r != -1 && (target_pid_fd = add_pollable_pid(epollfd, target_pid)) == -1) {
            if (errno == ESRCH) {
              fprintf(stderr, "process has died, quitting\n");
              return 0;
            }
            perror("pidfd_open");
          }
        }

        // TODO: kill() supports sending a signal to process group. maybe consider switching to
        // that for now? remember to keep eye on `pidfd_send_signal` changes.
        if (target_pid != -1) {
          int method_used = 0;
          if (target_pid_fd != -1) {
            method_used = 1;
            if (w_pidfd_send_signal(target_pid_fd, sig, NULL, 0) == -1) {
              if (errno == ESRCH) {
                fprintf(stderr, "process has died, quitting\n");
                return 0;
              }
              perror("pidfd_send_signal");
            }
          } else if (target_pid_fd == -1 && kill(target_pid, sig) == -1) {
            if (errno == ESRCH) {
              fprintf(stderr, "process has died, quitting\n");
              return 0;
            }
            perror("kill");
          }
        } else {
          fprintf(stderr, "child does not seem to be available yet\n");
        }
      } else if (target_pid != -1 && fd == target_pid_fd) {
        // *** Target process
        fprintf(stderr, "monitored pid %d exited, quitting\n", target_pid);
        if (remove_pollable_fd(epollfd, fd) == -1) {
          perror("epoll_ctl (failed to remove monitored process)");
        };

        close(target_pid_fd);
        target_pid = -1;
        target_pid_fd = -1;

        return 0;
      }
    }
  }

  return 0;
}
