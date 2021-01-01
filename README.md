# pidproxy

Lightweight signal forwarder for daemonizing programs.

Inspired from [supervisor][supervisor] project's [pidproxy script][supervisor-pidproxy-script]

## Features

- Signal rewriting
- Monitoring and signal processes using [pidfd\_open(2)][pidfd-open-2] & [pidfd\_send\_signal(2)][pidfd-send-signal-2]
- Small (When compiled statically with [musl libc][musl-libc], and packed with [upx][upx], binary is about 36 kilobytes on x86\_64) - Ideal for containers.

## Usage

```
USAGE: pidproxy [options] <path to pid file> <argv>
```

pidfd supports following optional arguments:
- `-g` - Whether to send signal to a process group or not.
- `-r from:to` - Rewrite a signal. Can be specified multiple times to rewrite multiple signals. Example: `-r 15:1`
- `-U uid/username` - Run target program as user. Can be either uid or username. Example: `-U game`
- `-G gid/group` - Override the group which program should run as. Can be either gid or group name. Example: `-G game`

### Usage within containers

Since pidproxy does not do process reaping like normal PID 1 would do, then I strongly recommend to launch pidproxy using an init process.

Here are few suggestions:
- [Use `--init` flag with Docker][docker-init]
- Use [dumb-init][dumb-init]
- Use [S6 overlay][s6-overlay]
- Cook your own using [go-reaper][go-reaper] for example

## Building

Run `make` to get statically compiled binary. You'll get best results using [musl libc][musl-libc] (Using `musl-gcc` wrapper is sufficient)

To use `musl-gcc`, do `CC=musl-gcc make`

Makefile also provides `pidproxy.upx` target, which produces packed executable using [upx][upx] (packed executable is usually ~50% smaller than original).

## Notes

1) Monitoring processes using [pidfd\_open(2)][pidfd-open-2] is not available in Docker containers before Docker engine version 20.10. Docker's default seccomp profile did not allow pidfd syscalls then.
Polling will be used instead then, causing possible PID race and makes pidfd exit bit later than monitored process.
2) Using `-g` flag to send a signal to the process group makes pidproxy use [kill(2)][kill-2] instead of [pidfd\_send\_signal(2)][pidfd-send-signal-2], which has possible PID race.

## License

GNU General Public License version 3

<!-- links -->
[docker-init]: https://docs.docker.com/engine/reference/run/#specify-an-init-process
[dumb-init]: https://github.com/Yelp/dumb-init
[go-reaper]: https://github.com/ramr/go-reaper/
[kill-2]: https://man7.org/linux/man-pages/man2/kill.2.html
[musl-libc]: https://www.musl-libc.org/
[pidfd-open-2]: https://man7.org/linux/man-pages/man2/pidfd_open.2.html
[pidfd-send-signal-2]: https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html
[s6-overlay]: https://github.com/just-containers/s6-overlay
[supervisor-pidproxy-script]: https://github.com/Supervisor/supervisor/blob/master/supervisor/pidproxy.py
[supervisor]: http://supervisord.org
[upx]: https://upx.github.io/
