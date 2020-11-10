#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "USAGE: %s <path to pid file> <argv>\n", argv[0]);
    return 1;
  }

  int r;
  char *pidfile_name = argv[1];

  // Copy argv
  char *new_argv[argc - 1];
  new_argv[argc - 2] = NULL;
  for (int i=2; i < argc; i++) {
    new_argv[i - 2] = strdup(argv[i]);
    memset(argv[i], 0, strlen(argv[i]));
  }

  pid_t direct_child = vfork();
  if (direct_child == -1) {
    perror("failed to vfork");
    return 1;
  } else if (direct_child == 0) {
    int r = execvp(new_argv[0], new_argv);
    int err = errno;
    if (r == -1) {
      perror("failed to execvp");
    }
    _exit(1);
    return 1;
  }

  for (int i = 0; i < (argc - 1); i++) {
    free(new_argv[i]);
    new_argv[i] = NULL;
  }

  int child_stat;
  do {
    r = waitpid(direct_child, &child_stat, 0);
  } while (r == -1 && errno == EINTR);

  if (r == -1) {
    perror("failed to waitpid");
    return 1;
  }

  if (WIFEXITED(child_stat)) {
    int exitcode = WEXITSTATUS(child_stat);
    if (exitcode != 0) {
      fprintf(stderr, "child exited with code %d, exiting\n", exitcode);
      return 1;
    }
  } else if (WIFSIGNALED(child_stat)) {
    int sig = WTERMSIG(child_stat);
    fprintf(stderr, "child got killed with signal %d, exiting\n", sig);
    return 1;
  }

  // Ignore further child processes
  signal(SIGCHLD, SIG_IGN);

  // Set up signal mask
  sigset_t mask, oldmask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGHUP);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGQUIT);
  sigaddset(&mask, SIGTERM);

  // Wait for the signal
  int caught_sig;
  sigprocmask(SIG_BLOCK, &mask, &oldmask);
  if ((r = sigwait(&mask, &caught_sig)) == -1) {
    perror("failed to sigwait");
    return 1;
  }
  sigprocmask(SIG_UNBLOCK, &oldmask, NULL);
  fprintf(stderr, "got signal %d\n", caught_sig);

  // Read the pid file
  FILE* pid_file = fopen(pidfile_name, "r");
  if (!pid_file) {
    fprintf(stderr, "failed to open pidfile '%s': %s\n", pidfile_name, strerror(errno));
    return 1;
  }

  pid_t target_pid = -1;
  do {
    r = fscanf(pid_file, "%d", &target_pid);
  } while (r == -1 && errno == EINTR);

  if (r == -1) {
    fprintf(stderr, "failed to open pidfile '%s': %s\n", pidfile_name, strerror(errno));
    return 1;
  }
  
  if (target_pid == -1) {
    fprintf(stderr, "could not find an usable pid\n");
    return 1;
  }

#ifndef _NDEBUG
  fprintf(stderr, "sending %d to %d\n", caught_sig, target_pid);
#endif
  if ((r = kill(target_pid, caught_sig)) == -1) {
    perror("failed to kill");
    return 1;
  };

  fclose(pid_file);

  // Since the process is very likely not our child, then poll child exit
  // TODO
  return 0;
}
