# Render with: vhs docs/demo.tape   (requires https://github.com/charmbracelet/vhs)
Output docs/demo.gif
Set Shell "zsh"
Set FontSize 15
Set Width 1100
Set Height 620
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Set Padding 20

Hide
Type "setopt interactivecomments; export PATH=$PWD/venv/bin:$PATH; clear"
Enter
Show

Type "# Aegis: an AI agent proposes an action; Aegis gates it before it runs"
Enter
Sleep 800ms

Type "aegis check kubectl --pretty --now 2026-09-22T14:00:00Z -- kubectl scale deploy api-server --replicas 20 -n prod"
Enter
Sleep 2500ms

Type "clear"
Enter
Type "# Same action, dry-run: never blocked, but reports what would happen"
Enter
Type "aegis check kubectl --pretty --now 2026-09-22T14:00:00Z -- kubectl scale deploy api-server --replicas 20 -n prod --dry-run=server"
Enter
Sleep 2500ms

Type "clear"
Enter
Type "# A poisoned rule (source doesn't back it) is quarantined, not obeyed"
Enter
Type "aegis check git --pretty --sources data/sources -- git push --force origin main"
Enter
Sleep 2500ms

Type "clear"
Enter
Type "# Unbounded SQL delete from an agent -> BLOCK; bounded -> ALLOW"
Enter
Type "aegis check sql --pretty --plan-constraints '' 'DELETE FROM users; DELETE FROM users WHERE id = 1'"
Enter
Sleep 3000ms
