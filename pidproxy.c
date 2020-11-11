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

inline int w_pidfd_open(pid_t pid, unsigned int flags) {
  return syscall(SYS_pidfd_open, pid, flags);
}

inline int w_pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags) {
  return syscall(SYS_pidfd_send_signal, pidfd, sig, info, flags);
}

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

#define add_pollable_pid(efd, pid) (add_pollable_fd(efd, w_pidfd_open(pid, 0)))

static int watch_target_process(int epfd, const char *pidfile_name,
                                pid_t *target_pid_ptr, int *target_pid_fd_ptr) {
  int r;
  FILE* pid_file = fopen(pidfile_name, "r");
  if (!pid_file) {
    fprintf(stderr, "failed to open pidfile '%s': %s\n", pidfile_name, strerror(errno));
    goto end;
  }

  pid_t target_pid = -1;
  int target_pid_fd = -1;

  // Read PID file from the file
  do {
    r = fscanf(pid_file, "%d", &target_pid);
  } while (r == -1 && errno == EINTR);
  fclose(pid_file);

  if (target_pid == -1) {
    perror("fscanf");
    goto end;
  }

  *target_pid_ptr = target_pid;

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

static uint32_t timer_cycles = 0;
static unsigned int exit_signals_caught = 0;

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "USAGE: %s [options] <path to pid file> <argv>\n", argv[0]);
    return 1;
  }

  int child_argv_start;
  int r, direct_child_fd, evts, epollfd, sigfd, timerfd, target_pid_fd;
  pid_t target_pid = -1;
  char *pidfile_name;
  uint64_t _dummy;
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

  if ((sigfd = add_pollable_fd(epollfd, signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC))) < 0) {
    fprintf(stderr, "failed to set up signalfd (%s error): %s\n", sigfd == -1 ? "signalfd" : "epoll_ctl", strerror(errno));
    return 1;
  }

  // Set up timer and make it tick after every 1 second
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

      if (execvp(argv[child_argv_start], &argv[child_argv_start]) == -1) {
        perror("execvp");
      }
      _exit(1);
    }

    if ((direct_child_fd = add_pollable_pid(epollfd, direct_child)) < 0) {
      if (errno != ESRCH) {
        fprintf(stderr, "failed to watch for direct child exit (%s error): %s\n", direct_child_fd == -1 ? "pidfd_open" : "epoll_ctl", strerror(errno));
      }
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
      if (fd == direct_child_fd) {
        // *** Direct child exit

        direct_child_fd = -1;
        close(direct_child_fd);
      } else if (fd == timerfd) {
        // *** Timer
        r = read(timerfd, &_dummy, sizeof(uint64_t));
        timer_cycles++;

        if (target_pid == -1) {
          if (timer_cycles > PIDFILE_MAX_WAIT_TIME) {
            fprintf(stderr, "target process did not appear after waiting for %d seconds\n", PIDFILE_MAX_WAIT_TIME);
            return 1;
          }

          // Try reading pidfile
          if ((r = watch_target_process(epollfd, pidfile_name, &target_pid, &target_pid_fd)) == -2) {
            fprintf(stderr, "process has died, quitting\n");
            return 0;
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

        // Try reading pidfile
        if (target_pid == -1) {
          if ((r = watch_target_process(epollfd, pidfile_name, &target_pid, &target_pid_fd)) == -2) {
            fprintf(stderr, "process has died, quitting\n");
            return 0;
          }
        }

        if (target_pid == -1) {
          fprintf(stderr, "child does not seem to be available yet\n");
          if (sig == SIGINT || sig == SIGQUIT || sig == SIGTERM) {
            exit_signals_caught++;
          }

          if (exit_signals_caught > 2) {
            fprintf(stderr, "got exit signal 3 times while child was not present, exiting\n");
            return 1;
          }
        } else {
          // TODO: kill() supports sending a signal to process group. maybe consider switching to
          // that for now? remember to keep eye on `pidfd_send_signal` changes.
          int method_used = target_pid_fd == -1 ? 0 : 1;
          if ((method_used == 0 ? kill(target_pid, sig) : w_pidfd_send_signal(target_pid_fd, sig, NULL, 0)) == -1) {
            if (errno == ESRCH) {
              fprintf(stderr, "process has died, quitting\n");
              return 0;
            }
            perror(method_used == 0 ? "kill" : "pidfd_send_signal");
          }
        }
      } else if (fd == target_pid_fd) {
        // *** Target process
        fprintf(stderr, "monitored pid %d exited, quitting\n", target_pid);

        close(target_pid_fd);
        target_pid = -1;
        target_pid_fd = -1;

        return 0;
      }
    }
  }

  return 0;
}
