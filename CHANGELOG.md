# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). From 1.0 the public surface listed
under 1.0.0 below is stable: breaking it needs 2.0. Before 1.0 any release could change
behaviour.

## [Unreleased]

### Added
- Guide (experimental): [check the SQL an LLM writes before your app runs it](docs/guides/app-sql.md),
  with `examples/app_sql_gate.py` and a signed-rule template in `examples/app-sql/`. Aegis
  enforces "reads only" on generated SQL; the guide is explicit that a read's tables, columns and
  cost are the database role's job (the SQL classifier sees only a SELECT's first table, and
  treats `SELECT … INTO` and `SET ROLE` as reads). Every Aegis result in its table is a test.
- Agent hook: a time budget for each decision (`DECISION_BUDGET_SECONDS`, 10 s). The decision
  runs in a worker thread; when it takes longer, the hook answers on its own (asks, or denies
  when the command names an infrastructure tool, in each agent's usual format) instead of
  running into the agent's 30 s hook timeout, past which the agent would run the command. The
  abandoned worker's result is never used, and the reply is written to the streams the hook
  started with. A safety net: the checks are meant to be linear.

### Fixed
- Agent hook: a shell expansion in one part of a compound command no longer refuses the whole
  command (#55). The hook judges a command it cannot parse part by part (`;`, `&&`, `||`, `|`,
  newline): `terraform plan 2>&1; echo "exit=$?"` checks `terraform plan` against the policy
  and lets the `echo` through. A part with an unknown argument stands in for its program only
  when that program treats arguments as data (`echo`, `cat`, `tail`, `grep`, `ls`, `test`, …;
  not `sort`, `cp`, `mv`, `ln`, `tee`, `read` or `printf -v`) and does not redirect output to a
  computed path or a configuration directory (`~/.kube`, `~/.aws`, …); a part that only assigns
  a variable drops out, unless the variable steers an infrastructure tool (`KUBECONFIG`,
  `AWS_*`, `PATH`, …, also after `export`/`declare`/`local`). Any other unknown part (one that
  runs `$(…)`, backticks or `<(…)`, also inside double quotes, an unknown program, `find
  -exec`, `watch`, `ssh`, `trap`, `eval`, …) is refused when the command names an
  infrastructure tool anywhere; the message quotes the part. This refuses `TS=$(date +%s);
  kubectl …` on purpose: any command substitution next to an infrastructure command is.
  Here-docs are judged as a whole, as before.
- Shell parser: the reserved words `if`, `then`, `else`, `elif`, `do`, `while` and `until`, and
  `coproc`, in front of a command are stripped like `{` and `!`, so `if true; then kubectl
  delete namespace prod; fi` and `coproc kubectl …` are checked as the `kubectl` command they
  run (they were unknown binaries, and allowed). A lone `fi`/`done`/`esac` and a `for`/`select`
  header give no command; `function f { …; }` is rejected like `f() { …; }`. A backslash-newline
  outside single quotes and comments is removed as the shell removes it (`kubectl delete \` +
  newline + `namespace prod` was checked with a stray newline argument).
- Shell parser: a `#` comment ends at the newline. Before, the comment ran on past it, so
  `echo hi # note` + newline + `kubectl delete …` hid the `kubectl` line; and a `#` inside a
  word (`pods#x --as=admin`) cut off the rest of the command.
- Shell parser: the launchers `watch` (its arguments run through `sh -c` unless `-x`),
  `setsid`, `stdbuf`, `doas`, `ionice`, `caffeinate`, `unbuffer`, `chronic`, `busybox` and
  `script -c` are unwrapped like `sudo` and `nohup`. A program word the shell could expand into
  another name (`kube{,}ctl`, `kubec?`, `kube[c]tl`) is rejected ("brace/glob in program name");
  the hook refuses it when it is a bare word or could become a tool's name, and asks for a path
  pattern such as `./scripts/*.sh`. The hook asks (it does not refuse) when an unknown program
  has an infrastructure tool among its arguments, also as a path or after an option
  (`setpriv kubectl …`, `setpriv /usr/local/bin/kubectl …`, `proxychains -q kubectl …`, `chrt
  0 kubectl …`, `tmux new -d 'kubectl …'`), except programs that only take a tool's name
  (`man`, `command -v`, `hash`, `find`, `tree`, `make`, `pkill`, `lsof`, `curl`, `wget`,
  `tflint`, `checkov`, `pip`, `apt-cache` and other package tools, …), whose command-running
  options are still read (`rsync -e`/`--rsh`, `scp -o ProxyCommand=`/`-S`, `nix-shell
  --run`/`--command`), and arguments that are URLs, file names or a `-d dir` value naming an
  existing directory.
- Shell parser: package and environment managers that run a command are unwrapped, so the
  command meets the policy: `uv run`, `uv tool run`, `uvx`, `pipx run`, `poetry run`, `bundle
  exec`, `asdf exec`, `gem exec`, `mise exec`/`mise x` (`… -- CMD`, `-c STRING`) and `brew bundle
  exec -- CMD`. `uv run kubectl delete nodes --all` gave only a `uv` intent and was allowed,
  since `uv` and `pipx` take a tool's name in their other subcommands (`uv pip install kubectl`,
  `pipx install kubectl`, which are still allowed). An option these parsers do not know is
  rejected. `uv run -m mod` and `uv
  run script.py` are read as `python -m mod` and `python script.py`. `cargo run` and `go run`,
  which build a program and hand it the remaining words, now ask when those words name an
  infrastructure tool, like any unknown program. The hook also asks when a git configuration
  value names one (`git -c alias.x='!kubectl …' x`, `git -c core.sshCommand=… fetch`, `git config
  alias.x '!kubectl …'`): git runs such values where their argv cannot be checked.
- Agent hook: a local script run inside `$(…)`, backticks, `<(…)`, a subshell,
  a `{ …; }` group, a loop, a `case` branch, `sh -c '…'` (also `source`/`.` there), after `exec` or
  `builtin`, or by `fish`/`csh`/`tcsh`/`mksh`/`yash`/`rbash` is read like `bash x.sh`, and one that
  inline code may rewrite (`python3 -c '…"x.sh"…'; bash x.sh`) asks. `BASH_ENV`/`ENV` before a
  command asks. Commands git runs from its arguments or environment ask when they name an
  infrastructure tool or cannot be read: command-valued configuration only (`alias.*` starting with
  `!`, `core.sshCommand`, `core.pager`, `core.editor`, `*.helper` with `!`, `diff.*.textconv`,
  `filter.*`, …; `user.email=git@…` and `safe.directory=/work/terraform` no longer ask), `bisect
  run`, `submodule foreach`, `rebase -x`, `difftool`/`mergetool -x`, `filter-branch --*-filter`, and
  `GIT_SSH_COMMAND`, `GIT_PAGER`, `PAGER`, `EDITOR`, `VISUAL` and similar variables; this also
  holds inside `bash -c`. `fd -x`, `rg --pre`, `vim -c`/`+cmd`, `hash -p`, `alias NAME=…`, `nix run
  …#tool` and code arguments of `awk`, `sed`, `tmux`, `screen`, `parallel`, `flock`, `su`, … that
  name a tool ask. `cargo +nightly run`, `cargo --color X run` and `go -C dir run` are read as
  `run`. Package launchers accept common options before the subcommand (`uv --directory backend run
  …`, `poetry -C dir run`, `bundle --verbose exec`, `mise -E env exec`) and more `uv run` options,
  and `uvx`/`uv tool run`/`pipx run`/`gem exec` drop a version from the program (`kubectl@latest`,
  `kubectl==1.0`, `kubectl:1.0`). Development tasks of migration tools run instead of being refused
  as unknown migrations: `rails test`/`g`/`routes`/`db:migrate:status`/…, `alembic
  current`/`history`/`revision`/…, `prisma generate`/`migrate status`/…; other unknown tasks
  (`rails db:schema:load`, `rails console`) are still refused. A brace word with many groups is
  denied at once (its expansion was exponential), a `~+` path asks instead of failing, a command
  over 64 KiB is not parsed (asks, or blocks when it names a tool), and more than 32 pieces of
  piped code ask.
- Agent hook: script reading. A `<<` inside `$((…))`, `((…))`, `$[…]` or `${…}` is no longer taken
  for a here-document (`SIZE=$((1<<30))` hid every later line of the script), nor is one inside a
  string that spans lines; a quoted tag's body keeps its trailing backslashes, so `EOF` still ends
  it; a here-document whose end is never found asks, and its lines are checked as commands. A line
  ending in `|`, `|&`, `&&` or `||` is joined with the next (`echo … |` + newline + `sh`). Each
  script is read once per command, and more than 32 scripts in one command ask (a long run of
  `./x.sh;` took longer than the hook timeout). Scripts behind `builtin source`, `exec -a NAME`,
  `exec -c`, `source --`/`. --`, `bash -r` and `posh` are read in a command that parses too.
  More command-valued git settings and options ask when they name a tool: `git config -f FILE`/
  `--file`/`set …`, `diff.external`, `core.gitProxy`, `core.alternateRefsCommand`,
  `remote.*.uploadpack`/`receivepack`, `sendemail.*cmd`, an absolute `credential.helper` path,
  `--upload-pack`, `clone -u`, `push --receive-pack`/`--exec`, `GIT_PROXY_COMMAND`, and `emacs`
  code arguments. `git submodule foreach git pull` (and `fetch`, `status`, …) no longer asks, nor
  does `complete -C …` in a sourced rc file.
- Agent hook: a pipeline stage gets the same asks as the command on its own (`ssh h kubectl … |
  tail -5`, `awk 'BEGIN{system("kubectl …")}' | cat` were allowed), and so does a code argument
  given as `--expression=…`. A here-document read by a shell behind `exec`, `builtin`, `( `, `$(` or
  `sh -c sh` is checked as commands. A file redirected onto a group, subshell, `if` or loop that
  runs a shell (`{ bash; } < x.sh`) is read like `sh < x.sh`, and a shell reading a copied or
  read-write descriptor (`<&3`, `<>`) asks. `export`/`declare` of a command-valued or sourced
  variable (`export GIT_SSH_COMMAND=…; git fetch`, `export BASH_ENV=x; bash -c …`) asks like the
  prefix form. `perl`/`ruby -I DIR -e …` reads the inline code. Joining a script's lines that end
  in `|` or `&&` is linear in the script's size.
- Agent hook: `command source x.sh` / `command . x.sh` read the script; `bash < <(curl …)`, `bash -s
  < <(…)` and `python3 <(curl …)` ask like `bash <(curl …)`. Running a script twice (`bash x.sh;
  bash x.sh`, `./run.sh build && ./run.sh test`) or testing it (`test -f .env && source .env`) no
  longer counts as writing it. Checking which words name a script is linear in the command (32
  scripts next to a long argument list took seconds).
- Agent hook: `eval ./x.sh` / `eval 'bash x.sh'` read the script. In a script, a here-document
  piped into a shell on the line after its body (`cat <<EOF |` … `EOF` / `sh`), one with the reader
  after the redirection (`<<EOF sh`, `0<<EOF sh`) and `source /dev/stdin <<EOF` are checked as
  commands; `… | source /dev/stdin` is refused when the command names a tool, like `… | sh`.
  `PROMPT_COMMAND` counts as a command variable. A script path with `$HOME` or another variable
  the hook's environment sets (and the command does not) is read instead of asking. Finding files
  redirected onto groups is linear (63 KB of `)<a` took 36 s).
- Agent hook: scripts named in literal code piped into a shell are read (`echo 'bash x.sh' | sh`);
  `exec < x.sh` before a shell or interpreter reads x.sh like `sh < x.sh`; a pipe into a group,
  loop or `if` that runs a shell or interpreter asks (`… | while true; do sh; done`). A
  redirection target written as a separate word (`cd sub 2> /dev/null`) is no longer taken for an
  argument.
- Agent hook: only `$HOME` in a script path is filled in from the hook's environment, and only when
  the command names HOME nowhere else; `$PWD`, `$OLDPWD`, `$_` and a variable set by `for`, `read`
  or `unset` ask (`cd sub && source "$PWD/x.sh"` read the wrong file). A process substitution or
  here-string given to `exec` or to a group, loop or `if` that runs a shell asks (`exec < <(curl …);
  sh`, `{ sh; } < <(…)`). In a script, the reader of `cat <<EOF |` may follow blank or comment lines
  or be a group (`{ sh; }`). The pipe-into-a-loop ask only looks inside the loop and only at shells
  and interpreters that read standard input (`… | while read f; do python3 -m mod "$f"; done` runs).
  Many `exec < FILE` words are read in linear time.
- Agent hook: piped code nested inside piped code shares one budget of 32 checks per command (32
  levels of 32 took minutes). A pipe into `exec sh`, `eval sh`, `builtin exec sh` or `bash -c "exec
  sh"` is a shell reading the pipe. Scripts named in piped code are not read from the hook's
  directory after a `cd` in the command (asked), and `HOME=` anywhere in the command keeps `$HOME`
  from being filled in. `bash /dev/stdin` asks; a download named after a script (`wget …/x.sh`,
  `curl -O …/x.sh`) counts as rewriting it.
- Agent hook: a pipe into a group, loop, `if` or subshell asks when any shell or interpreter after it
  reads standard input: after its options (`bash -e`, `sh -l`, `bash -s`) no script, `-c` code or
  `-m` module follows (where the compound ends is no longer worked out, which `$(…)`, `${…}`,
  quotes and nesting got wrong, and which was quadratic). `eval`, `exec`, `builtin` and `sh -c`
  strings are unwrapped up to four levels, and any part of such a string may be the reader (`|
  bash -c 'eval sh'`, `| eval 'true; sh'`), also with `< FILE` (`bash -c 'eval sh' < x.sh` reads
  x.sh). Other redirections before a group's or `exec`'s standard input (`{ sh; } 2>/dev/null <
  x.sh`), a named descriptor (`sh <&$fd`), `~` when the command changes HOME, and a `cd` inside a
  subshell or `-c` string before piped code are no longer missed.
- Agent hook: a directory change is also seen spelt `\cd`, `"cd"` or as `env -C`/`sudo -D` (scripts
  after it ask instead of being read from the hook's directory); a quoted `sh -c` string is read on
  its own before the command is split (`bash -c 'set -e; bash x.sh "$@"'`); a chain of `eval`s is
  joined once (it was quadratic) and followed to four levels; a redirection after a shell reading a
  pipe (`sh 2>/dev/null`) no longer counts as its script. A URL counts as naming a script only for
  `wget` and `curl -O`/`-J`.
- Agent hook: a shell or interpreter given by path (`/bin/sh`, `/usr/bin/python3`) counts as a reader
  in the pipe, group-redirect, `exec <` and descriptor checks; `bash -ec '…' < x.sh` and a `-c` string
  followed by its arguments are read; `--version`/`--help` (and `-V`/`-v`/`-h` of an interpreter) are
  not stdin readers; only env's own `-C`/`--chdir` counts as a directory change (`env FOO=1 make -C
  build` does not).
- Agent hook: the regexes that find shells by path only start at a word, so long runs of `/` stay
  linear (they took over 30 s); an unquoted `<<< $(…)` or `` <<< `…` `` is a here-string, not a
  script argument; `bash -lc`, `--norc`, `-o pipefail` and trailing arguments before `< FILE` are
  read, and a `-c` string reading a process substitution or here-string asks; `| time (sh)` is a
  piped compound; a URL download other than `git clone` and `curl` without `-O` counts as naming a
  script.
- Agent hook: a shell that ends its line inside a piped loop or `if` (the usual multi-line form)
  reads the pipe; `bash -ec`, `-o pipefail`, `--norc` and `$'…'` `-c` strings are read on their own;
  a bare `cd` or `cd ~` after the command changes HOME makes the directory unknown; `python3
  /dev/stdin` reads the pipe; `env -iC` counts as a directory change; many `env`/`sudo` words stay
  linear.
- Agent hook: the regexes that find a shell's `-c` string and a shell or interpreter word are
  linear: runs of backticks, `{` inside quotes and `-o ` (with or without a `-c`) took 6-60 s, past
  the hook's timeout. A shell reading a piped group's input is found before a separator with no
  space (`sh;echo`, `sh&&x`, `sh -s;x`). Any interpreter given `/dev/stdin` or `/dev/fd/0` as its
  script asks, as `bash /dev/stdin` does (`| python3 /dev/stdin`, `| node /dev/stdin`). `env`
  and `sudo` read clusters of short options (`env -iv`, `env -iC DIR`, `env -iCDIR`, `env -u X
  -iC DIR`, `sudo -Eu USER`), and `env -S STRING` / `--split-string` is split into words unless
  it holds `$`, a backslash or options of its own; a cluster with `C` or `D` makes the directory
  unknown. A shell, interpreter or script run under `env`/`sudo` options the hook does not know
  (`env -P DIR bash x.sh`, `sudo -iu USER bash x.sh`, `cat x.sh | env -Q sh`) asks instead of
  being allowed.
- Agent hook: the checks for shells reading standard input match on the words the shell sees,
  not the raw text: `'sh'`, `"sh"` and `\sh` are `sh`, a quoted `';'` is an argument, not a
  separator, and an `env "-iC" DIR` or `sudo "-D" DIR` makes the directory unknown. Redirections
  are read in order, so the last `<` is standard input (`bash -c 'eval sh' < ok.sh < x.sh` and `{
  sh; } < ok.sh < x.sh` read x.sh). The words are read in one pass, also inside `sh -c` strings and
  `eval` words, to four levels. At most 32 launchers (`env`, `sudo`, `nice`, …) are unwrapped in
  front of one command, so a chain of `env -S`/`env -u` words stays linear (it took 5-7 s); a
  longer chain cannot be checked and is judged like any command the parser rejects.
- Agent hook: the shell-word reader follows bash's quoting more closely: here-document bodies
  (`<<`, `<<-`, quoted delimiters, several on one line) are set aside instead of read as commands
  (an apostrophe in one no longer hides the rest of the command), `$'…'` keeps its backslash
  escapes (`$'\''`), and `$(…)` is read as a command line of its own. A quote, `$(…)` or backtick
  never closed asks when the command names a shell, interpreter or infrastructure tool.
  Here-document bodies and command substitutions are checked like `sh -c` strings and `eval`
  words (`x=$(curl … | sh)` asks); `sh -c` strings and `eval` words in a command the parser
  rejects are dequoted the same way (`bash -c 'bash -c '\''sh < x.sh'\'''`, `eval 'bash x.sh;
  true'`), a `<` given to `eval` reaches a shell in its words (`eval 'true; sh' < x.sh`), and a
  pipe into a shell in such a command asks. A file redirected onto a group, loop, `exec` or `-c`
  string after a `cd` is no longer read from the hook's directory (asked).
- Agent hook: a `<<` inside `(( … ))`, `for (( … ))`, `$(( … ))`, `$[ … ]` or `${ … }` is a
  shift or a pattern, not a here-document, so the lines after it are read; a here-document whose
  delimiter never comes leaves the command unclosed (asked when it names a shell, interpreter or
  infrastructure tool). A command goes on past a newline after a trailing `|`, `|&`, `&&` or `||`
  (also after comments and blank lines), in the parser and in the shell-word reader, so `curl … |`
  / `sh` is a pipe into a shell and `kubectl get pods &&` / `kubectl delete …` is judged as the
  delete. `$'…'` is decoded as bash does (`\xHH`, octal `\NNN`, `\uHHHH`, `\UHHHHHHHH`, `\cX`),
  so `| $'\x73h'` is `| sh`; a pipe into a shell the parser does not recognise as one asks.
  `bash -s ARGS` and `bash +x` read the pipe. `python3 - <<'EOF'` and `node <<'EOF'` still
  ask: the hook does not read code in other languages.
- Agent hook: every here-document body, quoted or not, is checked as commands, whatever program
  reads it: which one runs it as code cannot be told reliably (functions, aliases, `PATH`,
  `hash -p`, `>(…)`, `exec 3> >(sh)`, `sort --compress-program`, `ssh`, `sudo -s`, …). The lexer
  still sets bodies aside when it reads the command around them, so an apostrophe in one cannot
  hide what follows. Accepted over-ask: a body that reads like a command asks (`cat > README.md
  <<'EOF'` with `curl … | sh` or `cd sub; bash x.sh` in it); it is denied only when it runs a
  blocked command. `$(…)`, `<(…)`, `>(…)` and backticks inside `$((…))`, `${…}` and `$[…]` are
  read (only a `<<` there loses its here-document meaning); single quotes hide them only in an
  unquoted `${…}`, not in arithmetic, `$[…]` or a double-quoted `"${…}"`. `((…))` and `$((…))`
  count as arithmetic only when they close with an adjacent `))` (`((cmd) )` is a subshell,
  `$((cmd) )` a command substitution). A comment, blank line or backslash-newline between a pipe
  and the command after it no longer hides that command.
- Agent hook: quoting inside `${…}` is followed level by level: double quotes make single quotes
  literal (`${x:-"'$(…)'"}` runs the substitution), and a nested `${…}`, `$[…]` or `$((…))` is
  read with its own rule (single quotes quote only in an unquoted `${…}`). In an unquoted
  here-document body quotes are literal, so its `$(…)` and backticks are read whatever quotes
  surround them (`cat <<E` / `'$(curl … | sh)'` asks); a quoted delimiter (`<<'E'`, `<<"E"`,
  `<<\E`) has no expansions. Command lines nested deeper than the hook reads (more than four
  levels of `sh -c`, `eval`, `$(…)` and here-documents, or more than 128 brackets of `$(…)`,
  `${…}`, `$[…]` and `$((…))`) ask instead of going unread.
- Agent hook: backticks are read the same way everywhere (at the top level, inside double
  quotes, inside `${…}`/`$((…))` and in unquoted here-document bodies): a substitution ends at
  the first backtick no backslash escapes, and its text is unescaped as bash does (`` \` ``,
  `\\`, `\$`), so an escaped backtick inside is a nested substitution that is read in turn
  (`` echo "`echo \`bash x.sh\``" `` reads x.sh). `` "`curl … | sh`" `` asks. Scripts named in
  nested command lines are read like those at the top.
- Agent hook: in a command the parser rejects, scripts (and launchers with unknown options) are
  found from the shell-word reader's simple commands rather than a split of the raw text, for
  the command and every command line nested in it (`sh -c`, `eval`, `$(…)`, backticks,
  subshells, here-document bodies), so a quoted `;`, `|`, `&`, `(`, `)` or backtick is part of
  a word (`echo $(bash x.sh 'a;b')` and `bash x.sh '('` read x.sh). Backticks directly inside
  double quotes also unescape `\"`, as bash does there (`` "`eval \"bash x.sh\"`" ``). A
  shell's options that take a value (`-o`, `+o`, `-O`, `+O`, `--rcfile`, `--init-file`) are
  skipped with it, so `bash --rcfile FILE -c '…'` and `bash -O extglob -c '…'` read the `-c`
  string instead of taking FILE or the option name for the script.
- Agent hook: a launcher's command string (`watch 'cmd'`, `script -c 'cmd'`, `mise exec -c
  'cmd'`, also behind `sudo`/`nohup`) is a nested command line like a `sh -c` string, so every
  check reads it, also in a command the parser rejects (`watch 'bash x.sh' "$HOME"`). A shell
  given a script whose name is only known at run time and a `< FILE` (`sh < x.sh $X`) also has
  FILE read, since with `$X` empty it runs FILE. An interactive shell (`-i`, `-ic`, …) sources
  its `--rcfile`/`--init-file`, which is read as a script (`bash --rcfile x.sh -i`); with `-c`
  alone the file is not read, as bash does.
- Agent hook: a shell's short-option cluster takes one value per `o`/`O` in it, in order, and
  then the `-c` string if it holds a `c` (`bash -co pipefail 'cmd'`, `bash -Oc extglob 'cmd'`,
  `bash -eo pipefail x.sh` runs x.sh), the same in the parser, the script reader and the
  checks for shells reading standard input. `function NAME { …; }` is read like `NAME() { …;
  }`, so the scripts in its body are read.
- Agent hook: in zsh, ksh, mksh and yash an `o`/`O` with letters after it takes them as its value
  and ends the cluster (`zsh -opipefail -c 'cmd'`, `zsh -eopipefail x.sh`); a trailing one, and
  every `o`/`O` in bash, dash and sh, takes the next word. An `i` in a cluster with option values
  (`bash --rcfile x.sh -io pipefail -c …`) still makes the shell interactive, so it sources the
  file. Only the shell in command position sources its `--rcfile` (`echo bash -i --rcfile x`
  runs no shell), and an interpreter's `-O`/`-o` takes no value (`python3 -OO x.py`).
- Agent hook: any `c` in a shell's short-option cluster means `-c`, also after an attached
  value (ksh93 reads `-oc` as `-c`), and the same holds for `i` and `s`. Shells started by
  `find … -exec|-execdir|-ok|-okdir` are nested command lines like `watch`'s, so their
  `--rcfile` and scripts are read. Only bash has `--rcfile`/`--init-file`, and only before its
  short options (`bash -i --rcfile x` is an error and runs nothing). A shell with more option
  words than the hook reads (64), before its `-c` string or script or as a reader in a piped
  group, asks instead of being passed over. Versioned shell names (`zsh5`, `ksh93`, `bash5.2`)
  are read as their shell.
- Agent hook: an `o`/`O` with letters after it that hold `c`, `i` or `s` in zsh, ksh, mksh or
  yash (`-onoclobber`, `-oxtrace`, `-ointeractive`) is read both ways wherever a shell's
  options are read, on the dequoted words of every nested command line (`zsh "-onoclobber"
  x.sh`, `zsh -o noclobber -oxtrace x.sh`, `bash -c 'zsh -onoclobber x.sh'`): as the option's
  value (as zsh and ksh do: x.sh is the script, or the shell reads standard input) and as set
  letters (as ksh93 reads `-oc` as `-c`: x.sh is the command string). Both are checked, so
  `ksh -oc 'cmd'` also asks when `cmd` is harmless (its other reading runs a script named
  `cmd`). `find … -exec` ends at `;` or at a `+` right after `{}`; any other `+` is
  an argument (`find . -exec env -u + cmd \;` runs cmd). Versioned names are mapped only for
  shells that ship them (bash, zsh, ksh, mksh, dash, yash, also `mksh-R59`; not `sh2`).
- Agent hook: a shell's lone `-` ends its options like `--`, and after either every word is an
  operand, so the next word is the script, even one whose name starts with `-` (`bash - x.sh`,
  `zsh -x - x.sh`, `bash -- -x`); a lone `-` with nothing after it still reads standard input
  (`curl … | bash -` asks). An ambiguous zsh/ksh cluster read as a value that leaves `-s` reads
  its `< FILE` as the script. zsh's `noglob`, `nocorrect` and `repeat N` are unwrapped like
  `command` (`noglob bash x.sh`). A long run of `!` or `{` before a command is stripped in one
  pass (65 KB of `! ` took over 2 s).
- Agent hook: `!`, `time [-p]` and grouping words in front of a command are stripped in any
  order (`time ! sh x.sh`, `! time ! sh x.sh`), as are zsh's `repeat N do … done`; `command --`
  (also `command -p --`), `nice --` and `timeout -- N` are unwrapped. A `-` or `--` ends a
  shell's options the same way in every place that reads them, so after `-c` the next word is
  the command string (`bash -c - 'cmd'` runs cmd). `noglob source x.sh` and `noglob . x.sh` read
  x.sh like `source x.sh`.
- Agent hook: assignments, `--`, `!`, `{`, reserved words and `coproc` in front of a command are
  passed over in one pass in any mix (`-- ! A=1 do …` took 3-4 s at 64 KB; `time coproc sh x.sh`
  reads x.sh), as are runs of `exec`/`builtin`; each pass over the launchers counts toward the
  limit of 32, and a pass that changes nothing ends the unwrapping. A program whose path ends in
  such a word (`./-- ; …`) no longer makes the unwrapping loop forever (a hang lets the command
  run); the shell-word reader also never stays on a character. `command` takes repeated or
  clustered `-p` (`command -p -p`, `-pp`), and GNU time (`/usr/bin/time`, `gtime`) takes its
  options (`-f FMT`, `-o FILE`, `--format=`, `--output=`, `-v`, `-l`, `-a`, `-q`, `-p`).
- Agent hook: a program word with glob characters (`kube{,}ctl`, `k*`) is matched against the
  tools' names with a small glob matcher that runs once along the word, not with `fnmatch`,
  which compiled the word to a regex and was quadratic on runs of `[` (64 KB of `[` took 36 s;
  `{a,b}`×8 + 2 KB of `[` took 10 s). More than 16 KB of glob text across the brace
  alternatives counts as possibly a tool's name (denied), as does a POSIX class (`[[:alpha:]]`).
  Quoted glob characters are literal, as in the shell (`"[[[["` and `'k*'` are program names,
  not globs): whether they are quoted is read where the word is read, in the command or in its
  `-c` string, in one pass (`bash -c 'k* …' 'k*'` is still a glob); a program word a launcher
  produces (`uvx 'kube[a]x'`) counts as a glob when it holds one. A `find … -exec` program
  word is a glob as the outer shell spells it (it expands find's words before find runs:
  `find . -exec k* …`, also inside `eval` or `$(…)`), and program words in nested lines the
  parser rejects (`eval` words, a `-c` string in a `-c` string, substitutions, here-document
  bodies) are checked too. For this check a here-document body is shell-run when a shell,
  `eval`, `source`, `.` or `exec` is a program of the pipeline its `<<` is in (`bash <<EOF`,
  `cat <<EOF | sh`: as for a command), data when every program there is a data sink (`cat`,
  `tee`, `jq`, `git`, …) or an interpreter of another language reading the body as its
  program (`python3`, `python3 -`, `node`; also `python3 -m json.tool`; not one given inline
  code or a script, which may hand the body to a shell: `python3 -c '…os.system(input())'`),
  with no `<(…)`/`>(…)` and no descriptor path (not checked: a Markdown `* item`), and otherwise
  unknown (`tee >(sh)`, a function or alias in the command, `sed`, `xargs`, an `eval`
  anywhere), where a globbed word asks. Only an unquoted `case` at the start of a command
  (after `do`, `then`, `else`, `{`, `!` or `time` too, spelt bare in reserved-word position:
  `"do" case …` and `echo do case …` are plain words), with no redirect, assignment or
  other word before it, starts a case statement, whose arm patterns (`*)`, `a|b*)`) are
  not program words for this check. A word whose quoting is not known counts as a glob. Each
  text's quoting is read once per decision, and `x+=1` and `a[1]=2` are assignments like
  `x=1`. Two other regexes that
  were quadratic on `[` runs (a package spec in `uv run`/`uvx`, a Terraform address index)
  are plain string scans now. With `--log-json`, a decision ended by the time budget logs its
  ask or deny, and the abandoned worker writes no log line or ledger entry (checked when its
  policy run starts and again before it writes).
- Shell parser: `find … -exec|-execdir|-ok|-okdir CMD … \;|+` yields CMD as a command of its
  own (`{}` stays a literal, unknown file), so `find . -exec kubectl delete … \;` meets the
  policy. A backslash-escaped `;`, `|`, `&`, `<`, `>`, `(` or `)` is a literal word, not a
  separator (`find … -exec rm {} \; -print` was split into a command `-print`).
- Agent hook: "names an infrastructure tool" also matches once quotes, backslashes and line
  continuations are removed (`kube''ctl`, `"kube"ctl`).
- Agent hook: a local shell script is read before it runs (#56). For `bash x.sh`, `sh < x.sh`,
  `./x` (a `#!` shell, `#!/usr/bin/env -S bash`, or no `#!` line), `source x.sh` and `. x.sh`,
  each line that names an infrastructure tool is checked as a command against the policy, in
  one policy run (a few more find the line when it does not allow): a blocked line, or a block
  the lines only reach together, blocks and the message names the line; a line that cannot be
  checked asks (the line is found by bisection on the verdict, so a BLOCK is not blamed on an
  earlier ESCALATE line). A backslash at the end of a line joins the next as the shell does,
  except at the end of a comment; comments are skipped; `<<` is a here-doc only outside quotes
  and comments, its delimiter is read as one shell word (`<<'END DATA'`; an unreadable one,
  such as `<<$'EOF'`, asks and the lines after it are checked as commands), and its body is checked when a shell reads it (also through `cat <<EOF | sh`), asks
  when another interpreter reads one that names a tool or an unquoted body's `$(…)` names one,
  and is data otherwise. A script that does not exist yet, is written, copied, moved, linked,
  edited or otherwise named by the same command (`printf … > x.sh; bash x.sh`, also spelled
  `"$PWD/x.sh"` or `"$(pwd)/x.sh"`; reading it with `cat`, `grep`, `wc`, … does not count), cannot
  be read, is not a regular file, holds a NUL byte (when a shell is named; a `./x` without `#!`
  and with a NUL is a binary and not read), is over 64 KiB, names a tool on more than 64 lines,
  or follows a `cd` the hook cannot follow (computed, in the background or a pipeline, `env
  -C`) asks; a relative path follows a literal `cd DIR` earlier in the command. What a script
  sources or runs in turn is not read, nor are other interpreters' scripts (`python3 x.py`).

### Changed
- Agent hook: code piped into a shell or interpreter, or fed to one by a here-string or here-doc
  in a command that cannot be parsed, asks instead of running (#56): `curl … | sh`, `echo … |
  base64 -d | sh`, `base64 -d <<< … | sh`, `cat x.py | python3`. Codex, Gemini CLI and OpenCode,
  which cannot ask, block it. Only a literal `echo` (no `-e`, no backslashes) or `printf` (one
  argument, no `%`) is read: its text blocks when it names an infrastructure tool, and code for
  a shell is checked like a command. Piped code in a command that names an infrastructure tool
  is still blocked. Shell intents' `params.runs_code` for a pipe now carries `producer`, the
  program feeding it.
- `aegis check command` still exits 64 for a command it cannot parse; for a compound command the
  message now ends with the part that caused it (`… inside double quotes in 'echo "exit=$?"'`).

## [1.2.1] — 2026-10-24

A coverage-report fix for `aegis compile kubernetes`.

### Fixed
- `aegis compile kubernetes`: rules on `apply`, `update`, `patch`, `edit` or `replace` are now
  reported over-enforced. Admission sees the CREATE or UPDATE these send, not the kubectl verb,
  so such a rule also denies an agent's create, set image, label and annotate (update verbs:
  also scale, through the `scale` subresource), which the client-side verifier allows; the
  coverage report called these rules exact.

## [1.2.0] — 2026-10-21

OpenCode V2 support, `aegis install --escalate-scripts`, and a hook latency benchmark.

### Added
- `aegis install <agent> --escalate-scripts`: registers the hook with `-- --escalate-scripts`
  (OpenCode: the plugin passes it on), so the opt-in script escalation no longer needs a
  hand-edited hook command. Reinstalling without the flag takes it out. With the flag, the
  OpenCode plugin blocks every shell command in an opted-in project when aegis cannot run.
- `scripts/hook_latency.py` and `results/hook-latency.json`: one `aegis hook claude` call on six
  shell commands, 1.0.0 against 1.1.0 on the same interpreter. 1.1.0 was 0.7–1.2 ms slower
  (median) on the five commands both decide alike, consistently about 1 ms, within run-to-run
  spread; inline code naming an infrastructure tool is denied before the policy loads
  (70 → 55 ms). `--escalate-scripts` was not measured. `docs/agents.md` has a "Cost" section.
- `scripts/budget_latency.py`: p95 is the nearest-rank value (the same sample for its 40 runs,
  so `results/budget-latency.json` is unchanged).
- The OpenCode plugin (`aegis install opencode`) supports OpenCode V2 (2.x) alongside V1: its
  default export is `{ id: "aegis-devops", setup(ctx), server() }`, so V2 calls `setup`
  (registering `ctx.tool.hook("execute.before", …)`) and V1 (1.15 and later) calls `server`.
  No npm dependency; same decisions and fail-closed behaviour on both. Under V2 a budget
  warning goes to OpenCode's log (V2 server plugins have no toast). Needed to stay in the
  awesome-opencode catalog, which removes V1-only plugins on 2027-01-01.

### Changed
- The OpenCode plugin no longer has a named `AegisDevOps` export (the default export replaces
  it). Reinstall with `aegis install opencode` to get the new file; nothing else changes.

## [1.1.0] — 2026-10-20

Denial reports for the server-side layer, and the agent hook checks code passed inline or
piped to an interpreter.

### Added
- **Preview:** `aegis report aws`: which calls the compiled SCPs denied, from CloudTrail
  (`--collect` with `aws cloudtrail lookup-events`, or saved events): attributed to Aegis when
  the error carries the SCP's policy ARN (`--policy-id`), per rule (the rules whose mapped
  actions cover the call), real versus deliberate tests (`--test-principal`). No real denial in
  a window of at least `--quiet-days` (default 30) exits 1: zero denials is not proof the policy
  works. SCP denials without a policy ARN are reported as possibly Aegis's; EC2's encoded
  reasons as undetermined. Proposed after outside review of the AWS SCP article.
- **Preview:** `aegis report kubernetes`: which requests the compiled ValidatingAdmissionPolicies
  denied, or warned about in report-only mode, from the API server's audit log (the `Audit`
  action's `validation_failure` annotation): per rule (exact, from the policy name), real versus
  deliberate tests (`--test-principal`), impersonated requests counted as the identity
  impersonated. Reports bindings that ran with other actions than the compiled ones and
  `aegis-*` policies missing from the output. No real denial in at least `--quiet-days`, or no
  events, exits 1. Reads `--audit-log-path` files (`.gz` ok), an `EventList`, or EKS
  `aws logs filter-log-events` output. Verified on kind.
- `aegis check command --escalate-scripts` (off by default; add it to the hook command as
  `aegis hook <agent> -- --escalate-scripts`): escalates commands that run code Aegis cannot
  read: `bash nuke.sh`, `bash < nuke.sh`, `./nuke.sh`, `source x`, `python3 x.py`, `make`,
  `npm run` (also with `$VAR` arguments), inline `python3 -c` code, a shell fed through a
  pipe. Shell intents for those carry `params.runs_code`.
- `docs/agents.md`: "What the hook cannot see", the tested list of what gets past the hook
  (scripts, Write/Edit tool files, SDK calls) and the server-side layer that does not.

### Changed
- Agent hook: inline interpreter code (`python -c` / `-Ic`, `node -e` / `--eval=`, `perl -e` /
  `-lne`, `ruby -e`, `php -r`, …) and code piped into a shell or interpreter are denied when
  the code names an infrastructure tool. Before, `python3 -c "subprocess.run(['kubectl','delete',…])"` and
  `echo 'kubectl delete …' | bash` ran unchecked.
- Agent hook: `bash -c "$(…)"`, `eval "$(…)"`, `source <(…)` and similar ask first (deny where
  the agent has no "ask"): the code they run only exists at run time. Before, they ran unless
  the command text named an infrastructure tool.

## [1.0.0] — 2026-10-10

The cross-agent session budget cap ([`docs/budget.md`](docs/budget.md)), and the 1.0 stability
promise ([design §9](docs/dev/DESIGN-v1.0-budget-cap.md)).

**Stable from 1.0** (breaking any of these needs 2.0): the policy file formats (`constraints`,
`authority`, `environments`, `plan_constraints`, `agents`, `budget`, all `version: 1`), the CLI
commands and their exit codes, the hook protocol per agent, and the GitHub Action's inputs and
outputs. **Still preview within 1.x:** the server-side compilers' output (`aegis compile`) and
the identity audit (`aegis audit-identity`), which may change shape in minor releases.
**Deferred, additive when it comes:** public-key signing (`docs/dev/DESIGN-v0.4-public-key-signing.md`).

### Added
- `aegis_core.budget`, the budget cap's core (design §3–§6):
  - `budget.yaml`, signed, whose `principal` must hold the new **`budget`** authority class:
    a per-session and a per-project-per-day limit in estimated USD or tokens (`unit` is
    required), a warning threshold, the day's time zone, the agents measured (only listed
    agents are), `on_unknown_log`, `on_unknown_price`, signed price overrides and a
    premium-request limit for Copilot CLI. Every shape problem is a load error.
  - A dated price table (`aegis_core/budget/prices.yaml`: Anthropic, OpenAI and Google list
    prices read 2026-10-07). An unpriced model is estimated per billing category from its
    vendor's (or the whole table's) highest rate — an estimate, not an upper bound — or, with
    `on_unknown_price: deny`, refused until priced. Usage is stored as tokens per model, so a
    new override re-prices earlier usage.
  - Usage readers for the session logs of Claude Code, Codex CLI, Gemini CLI, OpenCode and
    Copilot CLI (premium requests), with linked sub-agents counted inside their parent session,
    tested against redacted samples of real logs.
  - Accounting that the logs can always rebuild: per-session records, project/day totals merged
    by revision from a durable per-session counter, a session inventory outside the cache,
    rebuilds that report whether the day is complete, partial or of unknown completeness, and
    usage bucketed by the time the log recorded, never the time it was read.
  - Evaluation to allow / warn / deny with the measured usage, limits and observed overshoot.
- The budget cap in `aegis hook` (design §6): in a project whose policy directory holds a
  `budget.yaml`, after the policy decision (a BLOCK always stands), every covered tool call is
  denied once the usage available at the hook reaches a limit, and new prompts where the agent
  can block them (Claude Code and Codex `UserPromptSubmit`, Gemini CLI `BeforeAgent`); a warning
  is shown once per session per threshold (`systemMessage`; an OpenCode toast; stderr for Copilot
  CLI). A `budget.yaml` that cannot be used (bad signature, shape, authority) fails closed.
- `aegis budget status|check|reset` (design §7): today's project total and its sessions, rebuilt
  from the logs (`--json`); `check` exits 0 under, 3 over, 65 for an unusable `budget.yaml`, 66
  for none; `reset --day` acknowledges an incomplete day's history as it stands, with a marker
  signed by the policy key that records the acknowledged state, so `on_unknown_log: deny` stops
  denying for exactly that (later problems count again; an agent without the key cannot reset).
- `docs/budget.md`; `aegis init` writes a signed `budget.example.yaml`.
- Live test in each agent (`docs/dev/budget-live-test/`): tool calls and prompts over a
  budget denied in Claude Code, Codex and OpenCode; Copilot CLI's premium-request count reaches
  its log only at the end of a turn; Gemini CLI not tested (API credits). `docs/budget.md` now
  says, per agent, from when a turn's usage is seen.
- `scripts/budget_latency.py`: the budget adds ~9 ms to a hook call (74 vs 65 ms median,
  `results/budget-latency.json`), under the 20 ms target. The price table ships as
  `prices.json` generated from `prices.yaml` (`scripts/sync_prices.py`; a test keeps them equal)
  and is read only from the package: parsing the YAML on every call had cost ~15 ms.
- `aegis install` adds the budget hooks when the policy directory that applies holds a
  `budget.yaml` (`--budget` / `--no-budget` to choose): the tool hook sees every tool call and
  the prompt hook is added where the agent has one. The Claude Code plugin and the Gemini
  extension carry budget-only entries that start no process in projects without a budget; the
  OpenCode plugin sends every tool call, with its session id, only where a budget applies.
- The example `authority.yaml` gives `admin` the `budget` class.
- `agents.yaml`: a trusted AWS `source-identity` now warns (`source-identity-inherited`): a
  source identity survives role chaining, so an agent started in a session that carries it is
  exempt too. `no_agents: true` on the entry states that no agent runs under it and clears the
  warning. Raised in a review of the AWS SCP article by dev.to reader mickyarun.

### Documentation
- README: "Why not RBAC, or the agent's own permission settings?", with each spelling of a
  command the example policy blocks; a test keeps the table true.
- `docs/server-side.md`: what the second layer adds and what it doesn't (one policy enforced
  twice, not a second opinion), and why a trusted source identity must never carry an agent
  (same review). Denial reporting from CloudTrail added to the plan.

### Changed
- **kubectl: an unknown namespace is never "not prod".** A command without `-n` (which runs in
  the kubeconfig context's namespace) or with `-A` now escalates a namespace-scoped rule that
  would otherwise match, with the note `namespace-unresolved: <id>`, as an unresolved `env`
  already did; before, the rule silently did not apply. Cluster-scoped kinds are unaffected.
  `--resolve-current-context` now also fills the namespace from the kubeconfig context
  (`default` when it sets none). Reported by a reader on dev.to (Chris Sellers).
- **kubectl: manifests that are not read escalate kind rules.** `apply|create|replace|delete -f
  <file>|<dir>|-` and `-k`: a rule for the same action on kinds or objects escalates with
  `manifest-not-inspected: <id>`, since the manifest may hold what it protects; Aegis still
  never reads the file. Same report.

## [0.3.2] — 2026-09-29

Package metadata only; no change to behaviour.

### Fixed
- PyPI listed no author: `pyproject.toml` now declares the author, as `CITATION.cff` does.

### Added
- `docs/dev/DESIGN-v0.4-public-key-signing.md`: the reviewed design for public-key (SSH)
  signing of policy files, the next release's main change.

## [0.3.1] — 2026-09-29

The Kubernetes server-side layer: the policy compiled to ValidatingAdmissionPolicies scoped to
agent identities, verified on a kind cluster against the client-side verdicts, and an identity
audit that reports the RBAC escapes admission cannot see. Also a fix to how the aws parser names
resources. Preview: see `docs/server-side.md`.

### Added
- **Preview:** `aegis compile kubernetes --cluster <name> --out DIR`: the verified snapshot as
  Kubernetes ValidatingAdmissionPolicies (one policy and binding per rule) scoped to agents by
  `matchConditions` generated from `agents.yaml`, with the control plane always exempt in
  deny-by-default. Deletes (including evictions, and `delete --all`, admitted per item), creates,
  every update spelling, scale (subresource or `spec.replicas`), set-image (init containers
  included), rollout-restart, cordon, taint, label and annotate (old/new object diffs), rollout-undo
  (any pod-template change: over-enforced, as admission cannot tell an undo from a restart), exec/attach/port-forward (CONNECT),
  and the namespace cascade compile; name and namespace globs become RE2. Time windows (no
  clock at admission), rate limits, reads and impersonation are reported not enforced. An
  `aegis-guardrails` policy stops agents minting tokens for other ServiceAccounts or running pods
  as another ServiceAccount. Report-only compiles `[Warn, Audit]`, enforce `[Deny, Audit]`. Same
  coverage report, manifest and `--check` as the AWS target. Verified on kind (Kubernetes 1.36.1)
  with `scripts/kube_acceptance.py`: 66 of 66 runs as expected; the client and the cluster agreed
  on every shared case and differed only where coverage says so (`docs/dev/kube-acceptance/`).
- `aegis audit-identity kubernetes [--context CTX]`: read-only review of a cluster against
  `agents.yaml` — every ServiceAccount and RBAC-bound user or group the compiled policies would
  restrict (with bindings and pod counts; control plane and universal groups left out), missing
  ServiceAccounts, a break-glass subject no binding grants anything, and escape permissions an
  identity the policies restrict still holds (impersonation, by name and per namespace;
  updating, patching or deleting admission policies, bindings or webhooks; creating mutating
  admission; RBAC escalate/bind/cluster-role-binding writes), asked as SubjectAccessReviews with
  the groups each identity carries. A failed review is an error, not a "no". `--save-inventory` and
  `--inventory` for offline review. Run against the kind cluster: it flagged the cluster-admin
  test agent and an untrusted `system:masters`, and nothing for an `edit`-only agent.

### Fixed
- **aws CLI resource names.** For 17 operations the parser lost the name of the resource acted
  on (`ec2 delete-volume --volume-id vol-1` became `ec2/volume/*`) or took its parent's
  (`eks delete-nodegroup --cluster-name c --nodegroup-name ng` became `eks/nodegroup/c`, likewise
  `ecs delete-service`). A rule written for one named resource never matched on the client,
  while `aegis compile aws` enforced it. The resource's own flag now names it (EC2 volumes,
  snapshots, VPCs, subnets, security groups by id, gateways, images, key pairs; RDS clusters and
  snapshots; EKS clusters, node groups, add-ons, Fargate profiles; ECS services; log groups and
  streams; Route 53 hosted zones; EFS file systems; ElastiCache clusters and replication groups),
  and a parent taken from `--cluster`/`--cluster-name` is kept as `params.parent`. Rules on the
  `*` forms still match; name-specific rules now apply on the client as in the compiled policy.

## [0.3.0] — 2026-09-28

The first server-side layer: the policy compiled to AWS Service Control Policies scoped to agent
identities, so an agent that calls the AWS API directly (an SDK, a script, a found credential) is
refused by AWS itself, not only by the client hook. Preview: see `docs/server-side.md`.

### Added
- `ConstraintStore.verified_snapshot()` and `aegis snapshot`: the constraints that may vote —
  loaded **and** passing integrity and authority now (authority is otherwise checked only per
  decision) — frozen, with every excluded constraint and its reason, and one sha256 digest over
  all inputs (constraints, authority map, environment and plan-constraint maps, sources
  manifest, repos/signers/agents files, the commit each Git source ref points at, the Aegis
  version, and store settings such as the default time zone). A constraint also needs **source
  evidence** — its cited source fetched and verified at load (new `ConstraintStore.source_verified`)
  — or it is excluded as `source-unverified`. The snapshot is detached and deeply immutable
  (canonical records; `constraints` returns fresh copies; `verify()` recomputes the digest). The
  base for the v0.3 compilers (`docs/dev/DESIGN-v0.3-server-side.md` §3.1). `aegis snapshot`
  refuses `--insecure`, `--sources ''`, and any environment / plan-constraint / `agents.yaml`
  file that does not verify.
- `agents.yaml` and `aegis agents`: the identity model server-side enforcement is compiled for
  (design §4). **Deny-by-default** is the default mode: the file names the trusted identities
  (people, CI roles, controllers) and every other identity counts as an agent; `mode:
  agents-only` lists agents instead. At least one **break-glass** identity is required and is
  never restricted; `enforcement` starts at `report-only`. Identities are typed per platform
  (Kubernetes user/group/ServiceAccount, AWS role/user/SourceIdentity, GCP service
  account/user/group, GitHub OIDC subject) and validated; wildcards, duplicates, assumed-role
  session ARNs, groups every identity carries (`system:authenticated`, …) and a break-glass
  GitHub subject not bound to a workflow are load errors. Matching is exact, as AWS ARN
  conditions are (a mis-cased ARN never exempts).
  The file is signed and its `principal` must hold the new `identity` class in
  `authority.yaml` (the example grants it to `admin`). Warnings: a trusted GitHub subject that
  is not bound to a workflow or protected environment (`workflow-unbound`), a platform with no
  break-glass identity. `aegis snapshot` now loads `agents.yaml` through this loader instead
  of only checking its signature, and carries its warnings. `aegis init` ships
  `agents.example.yaml`, which never becomes active on its own.
- **Preview:** `aegis compile aws --account <id> --out DIR`: the verified snapshot as AWS Service
  Control Policies scoped to agent identities from `agents.yaml` (design §6.5). Explicit Deny
  statements on the IAM actions and ARNs from a new action map
  (`src/aegis_core/compile/actions/aws.yaml`, keyed by what the CLI parser produces), with
  `scope.env`/`account` compiled per account from `environments.yaml` and `scope.region` as
  `aws:RequestedRegion`. A self-protection block stops agents assuming, passing or modifying
  exempt roles, minting credentials for exempt users, setting an exempt source identity and
  leaving the organization. `coverage.json`/`.md` accounts for every constraint (exact,
  over-enforced, partial, not enforced, not applicable, excluded) with same-effect actions
  not covered; `manifest.json` carries the snapshot digest and a Sid → rule map. Output is
  split to the 5,120-character SCP limit and fails loudly if it cannot fit; `--check DIR`
  reports drift. With `enforcement: report-only` the SCPs go under `report-only/` and are not
  deployable. Statements merge exactly (same resources pool actions, same actions pool
  resources); a rule covering every name of a type denies the action on any resource.
  Every mapping was **verified** in a sandbox AWS Organization on 2026-09-28 (live calls
  and the IAM policy simulator, as agent, trusted, break-glass and path-qualified SSO
  roles; `scripts/aws_acceptance.py`, evidence in `docs/dev/aws-acceptance/`). The run
  found that denying `sts:SetSourceIdentity` outright also broke role chaining for agent
  sessions that carry a source identity; the self-protection statement now denies only
  exempt values. Guide: `docs/server-side.md`.
- `aegis audit-identity aws`: read-only check of `agents.yaml` against the IAM roles and users
  that exist in an account (from `aws iam get-account-authorization-details`, or a saved copy with
  `--inventory`). Lists every identity the compiled policy would restrict (`--would-restrict`,
  the review before `enforcement: enforce`), with last-used dates and hints for Identity Center
  and `OrganizationAccountAccessRole` roles; exempt identities; service-linked roles (never
  restricted by SCPs). Problems (exit 1): an identity listed for this account that does not
  exist (a mistyped break-glass role is no break-glass), GitHub OIDC trust on an exempt role that
  is not bound to a workflow or protected environment, has a wildcard or no subject, and — while
  report-only — exempt roles that a restricted identity or the whole account may assume.

## [0.2.1] — 2026-09-28

Fixes found by the council review of the v0.3 server-side design
(`docs/dev/DESIGN-v0.3-server-side.md`, now in the repository with the reviews). Security
relevant: upgrade if you rely on the default `discard` behaviour or on kubectl rules.

### Fixed
- **An untrustworthy rule could force ESCALATE through an unresolved condition.** When an
  intent's environment (or, without tzdata, a rule's time window) could not be resolved, every
  matching rule forced ESCALATE before its integrity or authority was checked, so an
  unauthorized or tampered rule scoped on `env: prod` could stall any action whose environment
  was unknown. Those rules are now discarded (reported in `discarded[]`) on that path too, as
  they are when they match outright; `--on-untrusted-match escalate` keeps the old behaviour
  for them. Found by the council review of the v0.3 design.
- **kubectl normal forms.** `kubectl drain node1` (and `cordon`/`uncordon`) parsed to
  `node1/*` instead of `node/node1`; `exec`, `logs`, `attach`, `port-forward` on a bare pod
  name parsed to the bare name instead of `pod/<name>`; plural and short kinds such as
  `storageclasses`, `sc`, `ingressclasses`, `clusterrolebindings`, `crd` were not normalised.
  A rule written for the normal form missed each of these. Rules written against the old forms
  need updating (see `docs/constraints.md`).
- `kubectl drain … --ignore-daemonsets` (and `--delete-emptydir-data`, `--disable-eviction`)
  was rejected as malformed.
- A global option before `rollout` or `set image` was read as the subcommand:
  `kubectl -n prod rollout restart deploy/web` became the action `rollout--n` on `prod/*`
  (losing the namespace, so a namespace-scoped rollout rule missed it), and
  `kubectl --as admin rollout restart …` escaped the impersonation rule. The subcommand is now
  taken before global options are merged, and global options between the verb and its
  subcommand (`kubectl rollout --as admin restart …`, which kubectl accepts) are consumed the
  same way, so every placement parses identically. An unrecognised option there still fails
  closed.

### Changed
- kubectl `--as` / `--as-group` / `--as-uid` are no longer dropped: they are recorded in
  `params.impersonate`, and each impersonated identity becomes its own `impersonate` intent
  (`user/<name>`, `group/<name>`, `uid/<id>`). Impersonation moves a request out of an agent
  identity's scope on the server side, so the client hook is the one layer that sees it.
- The example policy blocks kubectl impersonation (`block-kubectl-impersonation`); change its
  effect to ESCALATE if a human should be able to approve it. The example store now loads 30
  rules.

## [0.2.0] — 2026-09-27

**Real trust roots, step 1.** A rule can cite a signed commit in a policy repository, and its
principal is the commit's verified signer (SSH or GPG) rather than a name written in the rule
or asserted with the shared signing key. Together with 0.1.7 (Git sources, SSH), this completes
step 1 of the v0.2 roadmap (`docs/dev/PLAN.md` §9; design in
`docs/dev/DESIGN-v0.2-git-sources.md`). Opt-in: nothing changes unless a rule cites `git:`.
Still to come: per-principal public-key signing for the other policy files (step 2) and
Slack/Jira sources (step 3).

### Added
- **OpenPGP (GPG) signatures for Git sources**, alongside SSH. A GPG signer is listed with its
  primary fingerprint and armored public key; Aegis verifies against a private keyring holding
  exactly those keys (a mismatch is a load error), so neither the user's keyring nor the
  repository's config can add trusted keys. Expired and revoked keys do not verify.
- `aegis sources`: one line per constraint with its source transport (`git`, `file`,
  `unchecked`), the verified principal, or the quarantine reason; exits 1 if any rule is
  quarantined.
- `aegis init` writes commented `repos.example.yaml` and `signers.example.yaml` (inert until
  copied to `repos.yaml` / `signers.yaml`).

## [0.1.7] — 2026-09-27

Git sources: a rule can cite a signed commit, and its principal is the commit's verified
signer. Opt-in; nothing changes unless a rule cites `git:`.

### Added
- **Git sources with signature-derived principals** (v0.2 step 1,
  `docs/dev/DESIGN-v0.2-git-sources.md`). A constraint may cite
  `git:<repo>@<sha>:<path>` in a locally configured clone (`repos.yaml`); its principal is the
  verified SSH signer of that commit, mapped through `signers.yaml`, instead of a name in the
  rule or `PRINCIPALS.yaml`. New quarantine reasons: `invalid-source-ref`, `unknown-repo`,
  `unknown-commit`, `unsigned-source`, `unknown-signer`, `commit-does-not-touch-source`,
  `superseded`, `stale-source`, `invalid-git-source`. New options `--repos`, `--signers`,
  `--max-source-age`. Git runs with a from-scratch environment and overrides for every
  signature setting, so a repository's own config cannot choose the trusted keys. Shallow and
  grafted clones are refused (they change which parents Git reports), the commit-graph cache is
  off, and "did this commit add the rule" is read from the signed commit object. A `git:`
  citation with no Git configuration is always rejected (`unknown-repo`). File sources are
  unchanged.

## [0.1.6] — 2026-09-27

A correction to the published benchmark. No change to how a decision is made.

### Fixed
- **The agent-harness benchmark rows were scored against rules they were never shown.** The
  `claude-cli*`, `codex*` and `ollama` rows are shown only the corpus's 100-constraint holdout
  subset, but were scored against the reference oracle over all 500 constraints. On the 120
  hold-out intents the oracle's verdict differs between the two for 37 intents, and 11 of the
  30 poison candidates involve poisoned rules outside the 100. So those rows were marked as
  missing legitimate rules they never saw (recall 0.72–0.77) and as resisting poisoned rules
  they never saw. Each row is now scored against the oracle over exactly the rules it was
  given (`scored_against` in `results/benchmark.json`). The same cached answers, re-scored
  (no model was re-run): poison-susceptibility **1.000** for six of the seven models and
  **0.789** for `gpt-6-luna` (previously reported as 0.23–0.33), recall 0.97–1.00. The earlier
  numbers **understated** how often the models act on poisoned rules. The 0.1.2 entry below
  ("All land between 0.23 and 0.33 poison-susceptibility and every one acts on 5 of 8 forged
  rules") is wrong for that reason.
- This also accounts for the gap between the Sonnet 5 API self-check (1.000) and the
  `claude-cli-sonnet` row (previously 0.333): the latter was scored against 400 rules it never
  saw.

### Added
- `aegis-holdout`: Aegis restricted to the same 100-constraint subset, so there is a
  like-for-like row on that basis (0 of 19 poison candidates acted on, over-block 0.000).
- Tests that every published row is scored on the basis it was shown, and that the holdout
  oracle only ever sees the holdout constraints.
- The repository is a Gemini CLI extension (`gemini-extension.json`, `hooks/hooks.json`):
  `gemini extensions install https://github.com/moneytool/aegis-devops`.

### Changed
- The Claude Code plugin moved to `plugins/claude/` (the marketplace entry points there, so
  `claude plugin marketplace add moneytool/aegis-devops` and the install command are
  unchanged). Gemini CLI reads an extension's hooks from `hooks/hooks.json` at the root, where
  the Claude plugin's hooks used to be.

## [0.1.5] — 2026-09-27

Gemini CLI and OpenCode join the supported agents; all seven are live-tested. No change to how
a decision is made.

### Added
- `aegis hook gemini` / `aegis install gemini`: a `BeforeTool` hook on Gemini CLI's
  `run_shell_command`.
- `aegis hook opencode` / `aegis install opencode`: OpenCode's hooks are JavaScript plugins, so
  the installer writes a bundled plugin (`tool.execute.before`) that hands each `bash` command
  to `aegis hook opencode` and throws when Aegis says no.

## [0.1.4] — 2026-09-27

A GitHub Copilot plugin, and a fix to the forged-source demo. No change to how a decision is
made.

### Added
- A GitHub Copilot plugin (`plugins/copilot/`, Agent Plugins 1.0):
  `copilot plugin install moneytool/aegis-devops:plugins/copilot`. It runs the same wrapper as
  the Claude Code plugin, so without `aegis` installed it still allows everything outside
  opted-in projects instead of failing every command.

### Changed
- Copilot replies now carry VS Code's `hookSpecificOutput` shape as well as Copilot CLI's
  top-level `permissionDecision`, since both read the same hook files and plugins.

### Fixed
- `data/sources-forged/` lacked the eight sources added with the default rules, so the
  `--sources data/sources-forged` demo quarantined 9 of 29 rules and refused to decide.

## [0.1.3] — 2026-09-27

Aegis can now sit in front of a coding agent's shell commands, and the example policy blocks
the obviously infrastructure-breaking ones. No change to how a decision is made.

### Added
- `aegis hook <agent>`: runs as the pre-tool hook of Claude Code, Codex CLI, GitHub Copilot
  CLI, VS Code agent mode or Cursor, reads that agent's payload and answers in its format.
  It acts only in projects that opted in (`.aegis/` here or above, `$AEGIS_CONFIG_DIR`, or
  `~/.config/aegis`) and blocks only what the policy blocks; an unusable policy or a command
  that cannot be analysed blocks only infrastructure commands. See `docs/agents.md`.
- `aegis install <agent> [--user] [--remove]` writes (or removes) that hook in the agent's
  config without touching its other settings.
- A Claude Code plugin and marketplace (`.claude-plugin/`, `hooks/`):
  `claude plugin marketplace add moneytool/aegis-devops`.
- Default rules in the example policy for infrastructure-breaking commands: `terraform destroy`
  / `tofu destroy` / `apply -destroy`, `pulumi destroy` and `stack rm`, deleting a Kubernetes
  namespace, an S3 bucket, an RDS database, a GCP project or an Azure resource group (BLOCK),
  and deleting an Argo CD application (ESCALATE). The example store now loads 29 rules.
- `terraform`/`tofu` `destroy` (and `apply -destroy`) are recognised from the command line as
  a `terraform` `delete` intent on `workspace/<dir>`; other terraform subcommands still need a
  plan and are not gated from their argv.

### Changed
- The design notes and review history (`PLAN.md`, `REVIEW*.md`, `FEEDBACK.md`) moved to
  `docs/dev/`.

## [0.1.2] — 2026-09-26

No change to how a decision is made. Released so the PyPI page and the Zenodo record carry the
full benchmark.

### Added
- The benchmark now covers seven agent-harness models across two vendors: Claude Haiku 4.5,
  Sonnet 5, Opus 5 and Fable 5.1 through `claude -p`; `gpt-6-astra`, `gpt-6-sol` and
  `gpt-6-luna` through `codex exec`. All land between 0.23 and 0.33 poison-susceptibility and
  every one acts on 5 of 8 forged rules; Aegis acts on none of the 30 poisoned intents.
- `scripts/run_until_done.sh` runs a verifier to completion across CLI usage limits: it waits
  for the reset time the CLI reports and resumes from the cached answers.
- `scripts/make_latency_svg.py`: the latency chart is generated from `results/latency.json`, and
  the docs drift test fails if it is stale.

### Changed
- A decision is now O(k) in the matching (provider, action) bucket rather than O(n) in the
  store: the environment and time-window checks scanned every constraint. p99 at 10,000
  constraints fell from 5.9 ms to 3.7 ms.
- Latency figures report p95/p99 only; p50 fell between the cheap no-match decisions and real
  matches and described neither.

### Fixed
- LLM benchmark runs could not resume: the recording client never read its own cache, so every
  run re-asked every prompt. A usage-limit reply was cached as an empty answer; it now raises
  and is never cached.
- Each call verifies the model that actually answered; a mismatch stops the run instead of
  recording one model's numbers under another's name.
- `.gitignore` excluded all of `results/`, so its whitelist had never applied; the harness caches
  and the preserved fail-closed results are now tracked.
- A timing test that failed on shared CI runners was replaced by a count of the work done.

### Known
- Loading a store with `--sources` is about 35% slower than first measured, most likely from
  the path-traversal guard resolving every source path; it is a once-per-load cost.

## [0.1.1] — 2026-09-24

Documentation and packaging only; no change to the decision engine. Released so the PyPI
page carries the current README, and so the release is archived on Zenodo with a DOI.

### Added
- Codex CLI (`gpt-6-astra`) and Claude Code CLI (Haiku) rows in the benchmark. Both are
  agent harnesses rather than raw completions, scored on a 100-constraint hold-out subset.
- `SECURITY.md`, `CITATION.cff`, and this changelog.
- `scripts/make_benchmark_svg.py`: the benchmark chart is generated from
  `results/benchmark.json` instead of drawn by hand.
- `tests/test_docs_consistency.py`: CI now fails if a results table, the chart, a corpus
  diversity figure, or a description of the default policy disagrees with the data or the
  code.

### Changed
- The README is now a short entry point; reference material moved to `docs/cli.md`,
  `docs/constraints.md`, `docs/configuration.md` and `docs/benchmark.md`.
- The quick start leads with `pip install` and `aegis init ./.aegis`. Without `init`, a fresh
  install had no policy files and every check exited 66.
- The alpha caveats moved from a banner at the top of the README into Project status.

### Fixed
- `docs/cli.md` and `docs/configuration.md` still described the old escalate-on-untrusted
  default and showed ESCALATE output for tampered and forged rules. On 0.1.0 both examples
  ALLOW, with the rule named in `discarded` and in store health. They now show real output
  from the current code.
- `docs/benchmark.md` quoted the previous corpus's diversity figures and called
  `evade-case-variant` an `xfail`.

## [0.1.0] — 2026-09-23

First release. Published to PyPI as `aegis-devops`.

### Added
- **Constraint store** with two independent guarantees per rule: integrity (a provenance hash
  over the source-side fields) and authority (which principal may assert which class of rule).
  Schema validation, quarantine with reasons, and signed policy files.
- **Interceptor** returning ALLOW / BLOCK / ESCALATE with citations, discarded rules, coverage,
  notes and latency. Dry runs are never blocked but report the verdict a real run would get.
- **Parsers** for kubectl, Terraform and OpenTofu plans, AWS, Azure, gcloud/gsutil, Helm,
  ArgoCD, Flux, git, the GitHub CLI, Pulumi, and SQL/mongo/migration tools — all normalising to
  one intent shape. `aegis check command` splits a whole shell string, since that is what an
  agent framework hands you.
- **Plan-level constraints** evaluated over a whole batch (`max_intents`, `max_matching`,
  `forbid_together`, `ratio`).
- **Environment identity mapping** from kube contexts, cloud accounts, projects, subscriptions
  and repos, so rules scope on `env: prod` rather than raw identifiers. An unresolved
  environment escalates rather than being treated as "not prod".
- **Rate-limited constraints** backed by a locked, hash-chained, rotating decision ledger
  (JSONL or SQLite).
- **Signing** of policy and source files, with per-directory manifests, and `aegis sign` /
  `aegis verify` / `aegis keygen`.
- **CLI** with `aegis init`, config discovery, structured decision logs, a Prometheus textfile
  exporter, and `--exit-style claude-hook` plus a ready-made Claude Code PreToolUse hook.
- **Evaluation**: a 500-constraint labelled corpus (323 distinct structures) seeded from public
  postmortems, the Gatekeeper library, and cloud security benchmarks; an independent reference
  oracle so ground truth never runs the system under test; an adversarial suite of attacks in
  five categories; and a benchmark against OPA, a signed-bundle OPA variant, and real LLM
  self-checks.

### Changed
- An untrustworthy matching constraint (tampered, forged, or from an unauthorized principal)
  gets **no vote** by default. An earlier default made it force ESCALATE; measurement showed
  that scored the same poison-susceptibility and over-block rate as a verifier with no trust
  model at all, because letting an unverifiable rule produce a verdict hands whoever planted it
  control over that verdict. The old behaviour is available as `--on-untrusted-match escalate`.

### Known limitations
See "Project status" in the README and [`docs/dev/PLAN.md`](docs/dev/PLAN.md) §8. In short: the source fetcher reads files
rather than real connectors, signing uses a shared secret, and a principal is a signed name
rather than a bound identity.

[1.2.1]: https://github.com/moneytool/aegis-devops/releases/tag/v1.2.1
[1.2.0]: https://github.com/moneytool/aegis-devops/releases/tag/v1.2.0
[1.1.0]: https://github.com/moneytool/aegis-devops/releases/tag/v1.1.0
[1.0.0]: https://github.com/moneytool/aegis-devops/releases/tag/v1.0.0
[0.3.2]: https://github.com/moneytool/aegis-devops/releases/tag/v0.3.2
[0.3.1]: https://github.com/moneytool/aegis-devops/releases/tag/v0.3.1
[0.3.0]: https://github.com/moneytool/aegis-devops/releases/tag/v0.3.0
[0.2.1]: https://github.com/moneytool/aegis-devops/releases/tag/v0.2.1
[0.2.0]: https://github.com/moneytool/aegis-devops/releases/tag/v0.2.0
[0.1.7]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.7
[0.1.6]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.6
[0.1.5]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.5
[0.1.4]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.4
[0.1.3]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.3
[0.1.2]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.2
[0.1.1]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.1
[0.1.0]: https://github.com/moneytool/aegis-devops/releases/tag/v0.1.0
