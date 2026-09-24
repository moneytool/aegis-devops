# Render with: vhs docs/demo.tape   (requires https://github.com/charmbracelet/vhs)
Output docs/demo.gif
Set Shell "zsh"
Set FontSize 15
Set Width 1180
Set Height 680
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms
Set Padding 20

Hide
Type "setopt interactivecomments; export PATH=$PWD/venv/bin:$PATH; clear"
Enter
Show

Type "# An AI agent proposes an action. Aegis decides before it runs."
Enter
Type "aegis check kubectl --pretty --now 2026-09-22T14:00:00Z -- kubectl scale deploy api-server --replicas 20 -n prod"
Enter
Sleep 3s

Type "clear"
Enter
Type "# Agents hand you a command string, not an argv. Each part is checked."
Enter
Type "aegis check command --pretty -- 'kubectl get pods; kubectl delete node/worker-1'"
Enter
Sleep 3500ms

Type "clear"
Enter
Type "# The point: a rule whose cited source does not back it gets NO vote."
Enter
Type "# Nobody can steer a decision by planting a rule -- in either direction."
Enter
Type "aegis check kubectl --pretty --sources data/sources-forged --now 2026-09-22T14:00:00Z -- kubectl scale deploy api-server --replicas 20 -n prod"
Enter
Sleep 4s

Type "clear"
Enter
Type "# It is still reported, loudly -- discarded, quarantined, store health."
Enter
Type "# Visibility, not obedience, is what makes a poisoned rule safe."
Enter
Sleep 2500ms

Type "clear"
Enter
Type "# Dry runs are never blocked, but report what the real run would get."
Enter
Type "aegis check kubectl --pretty --now 2026-09-22T14:00:00Z -- kubectl scale deploy api-server --replicas 20 -n prod --dry-run=server"
Enter
Sleep 3s

Type "clear"
Enter
Type "# Unbounded SQL delete -> BLOCK. Bounded -> ALLOW."
Enter
Type "aegis check sql --pretty --plan-constraints '' 'DELETE FROM users; DELETE FROM users WHERE id = 1'"
Enter
Sleep 4s
