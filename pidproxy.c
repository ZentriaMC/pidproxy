#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
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
  if (pid_file) {
    do {
      r = fscanf(pid_file, "%d", &target_pid);
    } while (r == -1 && errno == EINTR);
    r = target_pid;

    if (target_pid == -1) {
      fprintf(stderr, "could not find an usable pid from '%s'\n", pidfile_name);
    }
    fclose(pid_file);
  } else {
    fprintf(stderr, "failed to open pidfile '%s': %s\n", pidfile_name, strerror(errno));
  }
 end:
  return r;
 }

static uint32_t timer_cycles = 0;

int main(int argc, char **argv) {
  int r;
  char *pidfile_name;
  struct epoll_event events[MAX_EVENTS];

  if (argc < 3) {
    fprintf(stderr, "USAGE: %s <path to pid file> <argv>\n", argv[0]);
    return 1;
  }

  pidfile_name = argv[1];

  int evts, epollfd, sigfd, timerfd, target_pid_fd;
  pid_t target_pid = -1;
  struct signalfd_siginfo last_siginfo;

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

      if (execvp(argv[2], &argv[2]) == -1) {
        perror("execvp");
      }
      _exit(1);
    }
  }

  // Clear argv
  for (int i = 2; i < argc; i++) {
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
            fprintf(stderr, "target process pid appears to be %d\n", target_pid);

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

        int sig = last_siginfo.ssi_signo;
        fprintf(stderr, "got signal %d\n", sig);

        if (target_pid == -1) {
          fprintf(stderr, "loading pidfile immediately\n");

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
          fprintf(stderr, "signal proxied to %d using %s\n", target_pid, method_used ? "pidfd_send_signal" : "kill");
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
