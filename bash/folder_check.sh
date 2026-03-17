/*

cat << 'EOF' > ls_script.sh
#!/bin/bash

DIR="/opt/nessus_agent/var/nessus/triggers"
SLEEP_SECS=120
BAR_WIDTH=30

progress_sleep () {
  local secs="$1"
  local i filled empty pct
  for ((i=1; i<=secs; i++)); do
    pct=$(( i * 100 / secs ))
    filled=$(( i * BAR_WIDTH / secs ))
    empty=$(( BAR_WIDTH - filled ))

    printf "\rSleeping: ["
    printf "%0.s=" $(seq 1 "$filled")
    printf "%0.s " $(seq 1 "$empty")
    printf "] %3d%% (%ds/%ds)" "$pct" "$i" "$secs"

    sleep 1
  done
  echo
}

while true; do
  echo "[$(date)] Checking $DIR"

  if [ -z "$(ls -A "$DIR" 2>/dev/null)" ]; then
    echo "[$(date)] Directory is empty. Exiting."
    break
  fi

  ls "$DIR"
  echo "[$(date)] Not empty. Waiting 2 minutes..."
  progress_sleep "$SLEEP_SECS"
done
EOF

chmod +x ls_script.sh
./ls_script.sh

*/