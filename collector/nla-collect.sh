#!/usr/bin/env bash
# Netskope Log Analyzer — coletor de telemetria para Linux e macOS
#
# Grava amostras em JSON Lines (mesmo formato do coletor do Windows) para análise no
# Netskope Log Analyzer junto com o pacote de logs do Netskope Client:
#   CPU, memória, disco, bateria, Wi-Fi (sinal/RSSI/taxa/AP), tráfego, processos,
#   ping/perda/jitter, conexão TCP até os POPs, DNS, testes HTTP por fase (curl),
#   traceroute até o POP e eventos (troca de gateway/DNS/Wi-Fi, status do Netskope).
#
# Uso:
#   ./nla-collect.sh [-t tenant] [-i intervalo_s] [-p probes_s] [-r trace_min] [-d duracao_min] [-u url]... [-o pasta]
#   ./nla-collect.sh --install   [opções]   # coleta contínua (systemd --user no Linux, LaunchAgent no macOS)
#   ./nla-collect.sh --uninstall
#
# Exemplo: ./nla-collect.sh -t acme -d 60
# Saída padrão: ~/nla-telemetry/nla-telemetry-<host>-<AAAAMMDD>.jsonl (mantém 14 dias)

VERSION="3.0.0"
INTERVAL=30; PROBE=60; TRACE_MIN=15; DURATION=0; TENANT=""; OUT="$HOME/nla-telemetry"; RETENTION=14
URLS=()
ACTION="run"
ORIG_ARGS=("$@")

while [ $# -gt 0 ]; do
  case "$1" in
    -t) TENANT="$2"; shift 2 ;;
    -i) INTERVAL="$2"; shift 2 ;;
    -p) PROBE="$2"; shift 2 ;;
    -r) TRACE_MIN="$2"; shift 2 ;;
    -d) DURATION="$2"; shift 2 ;;
    -u) URLS+=("$2"); shift 2 ;;
    -o) OUT="$2"; shift 2 ;;
    --install) ACTION="install"; shift ;;
    --uninstall) ACTION="uninstall"; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "opção desconhecida: $1" >&2; exit 2 ;;
  esac
done
[ ${#URLS[@]} -eq 0 ] && URLS=("https://www.microsoft.com" "https://www.google.com" "https://outlook.office.com")

OS="$(uname -s)"
HOST="$(hostname -s 2>/dev/null || hostname)"
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

# ------------------------------------------------------------------ instalação como serviço

if [ "$ACTION" = "install" ] || [ "$ACTION" = "uninstall" ]; then
  ARGS=()
  for a in "${ORIG_ARGS[@]}"; do [ "$a" != "--install" ] && [ "$a" != "--uninstall" ] && ARGS+=("$a"); done
  if [ "$OS" = "Darwin" ]; then
    PL="$HOME/Library/LaunchAgents/com.netskope-log-analyzer.collector.plist"
    launchctl unload "$PL" 2>/dev/null; rm -f "$PL"
    if [ "$ACTION" = "install" ]; then
      mkdir -p "$HOME/Library/LaunchAgents"
      {
        echo '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
        echo '<plist version="1.0"><dict><key>Label</key><string>com.netskope-log-analyzer.collector</string>'
        echo "<key>ProgramArguments</key><array><string>/bin/bash</string><string>$SELF</string>"
        for a in "${ARGS[@]}"; do echo "<string>$a</string>"; done
        echo '</array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>'
      } > "$PL"
      launchctl load "$PL" && echo "Coleta contínua ativada (LaunchAgent)."
    else echo "Coleta contínua desativada."; fi
  else
    UD="$HOME/.config/systemd/user"; SV="$UD/nla-collector.service"
    systemctl --user disable --now nla-collector.service 2>/dev/null; rm -f "$SV"
    if [ "$ACTION" = "install" ]; then
      mkdir -p "$UD"
      printf '[Unit]\nDescription=Netskope Log Analyzer - coletor de telemetria\n\n[Service]\nExecStart=/bin/bash %s %s\nRestart=always\nRestartSec=30\n\n[Install]\nWantedBy=default.target\n' "$SELF" "${ARGS[*]}" > "$SV"
      systemctl --user daemon-reload && systemctl --user enable --now nla-collector.service && echo "Coleta contínua ativada (systemd --user)."
    else systemctl --user daemon-reload 2>/dev/null; echo "Coleta contínua desativada."; fi
  fi
  exit 0
fi

# ------------------------------------------------------------------ utilitários

mkdir -p "$OUT" || exit 1
find "$OUT" -name 'nla-telemetry-*.jsonl' -mtime +"$RETENTION" -delete 2>/dev/null
have() { command -v "$1" >/dev/null 2>&1; }

ts() {
  if [ "$OS" = "Darwin" ]; then date +%Y-%m-%dT%H:%M:%S%z | sed -E 's/([+-][0-9]{2})([0-9]{2})$/\1:\2/'
  else date +%Y-%m-%dT%H:%M:%S.%3N%:z; fi
}
now_ms() { if [ "$OS" = "Darwin" ]; then perl -MTime::HiRes=time -e 'printf "%d", time*1000'; else echo $(( $(date +%s%N) / 1000000 )); fi; }

jstr() { # string JSON escapada
  local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="$(printf '%s' "$s" | tr -d '\000-\037')"; printf '"%s"' "$s"
}
jnum() { case "$1" in ''|*[!0-9.-]*) printf 'null' ;; *) printf '%s' "$1" ;; esac; }

FILE=""; FILEDAY=""
emit() { # emit <k> <campos JSON já formatados, sem chaves>
  local day; day="$(date +%Y%m%d)"
  if [ "$day" != "$FILEDAY" ]; then
    FILEDAY="$day"; FILE="$OUT/nla-telemetry-$HOST-$day.jsonl"
    printf '{"t":"%s","k":"meta","host":%s,"os":%s,"cpu":%s,"cores":%s,"ramMb":%s,"model":%s,"collector":%s,"interval":%s,"tenant":%s}\n' \
      "$(ts)" "$(jstr "$HOST")" "$(jstr "$(os_name)")" "$(jstr "$(cpu_name)")" "$(cores)" "$(ram_mb)" "$(jstr "$(model)")" "$(jstr "sh-$VERSION")" "$INTERVAL" "$(jstr "$TENANT")" >> "$FILE"
  fi
  if [ -n "$2" ]; then printf '{"t":"%s","k":"%s",%s}\n' "$(ts)" "$1" "$2" >> "$FILE"
  else printf '{"t":"%s","k":"%s"}\n' "$(ts)" "$1" >> "$FILE"; fi
}
event() { emit event "\"type\":$(jstr "$1"),\"detail\":$(jstr "$2")"; }

os_name() {
  if [ "$OS" = "Darwin" ]; then echo "macOS $(sw_vers -productVersion 2>/dev/null)"
  elif [ -r /etc/os-release ]; then . /etc/os-release; echo "${PRETTY_NAME:-Linux} (kernel $(uname -r))"
  else uname -sr; fi
}
cpu_name() {
  if [ "$OS" = "Darwin" ]; then sysctl -n machdep.cpu.brand_string 2>/dev/null
  else awk -F: '/model name/{gsub(/^ +/,"",$2); print $2; exit}' /proc/cpuinfo 2>/dev/null; fi
}
cores() { if [ "$OS" = "Darwin" ]; then sysctl -n hw.ncpu; else nproc 2>/dev/null || echo 1; fi; }
ram_mb() { if [ "$OS" = "Darwin" ]; then echo $(( $(sysctl -n hw.memsize) / 1048576 )); else awk '/MemTotal/{printf "%d", $2/1024}' /proc/meminfo; fi; }
model() {
  if [ "$OS" = "Darwin" ]; then sysctl -n hw.model 2>/dev/null
  else echo "$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null) $(cat /sys/class/dmi/id/product_name 2>/dev/null)" | sed 's/^ *//; s/ *$//'; fi
}

# ------------------------------------------------------------------ dispositivo

PREV_TOTAL=0; PREV_IDLE=0
sample_cpu() {
  if [ "$OS" = "Darwin" ]; then
    local idle; idle="$(top -l 2 -n 0 -s 1 | awk '/CPU usage/{v=$7} END{gsub("%","",v); print v}')"
    [ -n "$idle" ] && emit cpu "\"v\":$(awk -v i="$idle" 'BEGIN{printf "%.1f", 100-i}')"
    return
  fi
  local a total idle
  read -r a u n s i w q sq st _ < /proc/stat
  total=$((u+n+s+i+w+q+sq+st)); idle=$((i+w))
  if [ "$PREV_TOTAL" -gt 0 ] && [ "$total" -gt "$PREV_TOTAL" ]; then
    emit cpu "\"v\":$(awk -v t=$((total-PREV_TOTAL)) -v d=$((idle-PREV_IDLE)) 'BEGIN{printf "%.1f", 100*(t-d)/t}')"
  fi
  PREV_TOTAL=$total; PREV_IDLE=$idle
}

sample_mem() {
  if [ "$OS" = "Darwin" ]; then
    local total; total=$(sysctl -n hw.memsize)
    vm_stat | awk -v total="$total" '
      /page size of/ {ps=$8}
      /Pages active/ {gsub("\\.","",$3); a=$3} /Pages wired/ {gsub("\\.","",$4); w=$4}
      /occupied by compressor/ {gsub("\\.","",$5); c=$5}
      END { used=(a+w+c)*ps; printf "\"usedPct\":%.1f,\"availMb\":%d,\"totalMb\":%d", 100*used/total, (total-used)/1048576, total/1048576 }' \
      | { read -r f; emit mem "$f"; }
  else
    awk '/MemTotal/{t=$2} /MemAvailable/{a=$2} /CommitLimit/{cl=$2} /Committed_AS/{ca=$2}
      END { printf "\"usedPct\":%.1f,\"availMb\":%d,\"totalMb\":%d,\"commitPct\":%.1f", 100*(t-a)/t, a/1024, t/1024, (cl>0?100*ca/cl:0) }' /proc/meminfo \
      | { read -r f; emit mem "$f"; }
  fi
}

sample_disk() {
  df -P -k -l 2>/dev/null | awk 'NR>1 && $2 >= 1048576 && $1 !~ /^(tmpfs|devtmpfs|udev|overlay|none|map|devfs)$/ && $6 !~ /^\/(snap|run|sys|dev|boot\/efi)/ && $6 !~ /^\/System\/Volumes\/(VM|Preboot|Update|xarts|iSCPreboot|Hardware)/ {
      used=$5; gsub("%","",used); printf "%s %s %.1f %.1f\n", $6, used, $4/1048576, $2/1048576 }' \
  | while read -r mnt used free total; do
      emit disk "\"d\":$(jstr "$mnt"),\"usedPct\":$(jnum "$used"),\"freeGb\":$(jnum "$free"),\"totalGb\":$(jnum "$total")"
    done
}

LAST_AC=""
sample_battery() {
  local pct="" ac=""
  if [ "$OS" = "Darwin" ]; then
    local b; b="$(pmset -g batt 2>/dev/null)"
    pct="$(echo "$b" | grep -Eo '[0-9]+%' | head -1 | tr -d %)"
    echo "$b" | grep -q "AC Power" && ac=true || ac=false
  else
    for d in /sys/class/power_supply/BAT*; do [ -r "$d/capacity" ] && pct="$(cat "$d/capacity")" && break; done
    for d in /sys/class/power_supply/AC* /sys/class/power_supply/ADP*; do [ -r "$d/online" ] && { [ "$(cat "$d/online")" = "1" ] && ac=true || ac=false; break; }; done
  fi
  [ -z "$pct" ] && return
  emit battery "\"pct\":$(jnum "$pct"),\"ac\":${ac:-null}"
}

WIFI_IF=""
sample_wifi() {
  if [ "$OS" = "Darwin" ]; then
    local AP=/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport
    [ -x "$AP" ] || return
    local o; o="$("$AP" -I 2>/dev/null)"; [ -z "$o" ] && return
    local rssi ssid bssid rate ch
    rssi="$(echo "$o" | awk -F': ' '/agrCtlRSSI/{print $2}')"; ssid="$(echo "$o" | awk -F': ' '/ SSID/{print $2}')"
    bssid="$(echo "$o" | awk -F': ' '/BSSID/{print $2}')"; rate="$(echo "$o" | awk -F': ' '/lastTxRate/{print $2}')"; ch="$(echo "$o" | awk -F': ' '/channel/{print $2}')"
    if [ -z "$ssid" ]; then emit wifi '"connected":false'; return; fi
    emit wifi "\"connected\":true,\"ssid\":$(jstr "$ssid"),\"bssid\":$(jstr "$bssid"),\"rssi\":$(jnum "$rssi"),\"signal\":$(jnum "$(sig_pct "$rssi")"),\"tx\":$(jnum "$rate"),\"ch\":$(jstr "$ch")"
    return
  fi
  if have iw; then
    [ -z "$WIFI_IF" ] && WIFI_IF="$(iw dev 2>/dev/null | awk '/Interface/{print $2; exit}')"
    [ -z "$WIFI_IF" ] && return
    local o; o="$(iw dev "$WIFI_IF" link 2>/dev/null)"
    if echo "$o" | grep -q "Not connected"; then emit wifi '"connected":false'; return; fi
    local ssid bssid sig rx tx freq band
    ssid="$(echo "$o" | awk -F': ' '/SSID/{print $2; exit}')"; bssid="$(echo "$o" | awk '/Connected to/{print $3; exit}')"
    sig="$(echo "$o" | awk '/signal:/{print $2; exit}')"; rx="$(echo "$o" | awk '/rx bitrate:/{print $3; exit}')"; tx="$(echo "$o" | awk '/tx bitrate:/{print $3; exit}')"
    freq="$(echo "$o" | awk '/freq:/{print int($2); exit}')"
    if [ -n "$freq" ]; then if [ "$freq" -lt 3000 ]; then band="2,4 GHz"; elif [ "$freq" -lt 5925 ]; then band="5 GHz"; else band="6 GHz"; fi; fi
    [ -z "$ssid" ] && return
    emit wifi "\"connected\":true,\"iface\":$(jstr "$WIFI_IF"),\"ssid\":$(jstr "$ssid"),\"bssid\":$(jstr "$bssid"),\"rssi\":$(jnum "$sig"),\"signal\":$(jnum "$(sig_pct "$sig")"),\"rx\":$(jnum "$rx"),\"tx\":$(jnum "$tx"),\"band\":$(jstr "$band"),\"ch\":$(jstr "$freq MHz")"
  elif have nmcli; then
    local l; l="$(nmcli -t -f IN-USE,SSID,BSSID,SIGNAL,CHAN,RATE dev wifi 2>/dev/null | grep '^\*' | head -1)"
    [ -z "$l" ] && { nmcli -t -f TYPE,STATE dev 2>/dev/null | grep -q '^wifi:' && emit wifi '"connected":false'; return; }
    l="${l//\\:/-}"
    IFS=: read -r _ ssid bssid sig ch rate <<< "$l"
    emit wifi "\"connected\":true,\"ssid\":$(jstr "$ssid"),\"bssid\":$(jstr "${bssid//-/:}"),\"signal\":$(jnum "$sig"),\"rx\":$(jnum "${rate%% *}"),\"ch\":$(jstr "$ch")"
  fi
}
sig_pct() { [ -z "$1" ] && return; awk -v d="$1" 'BEGIN{p=2*(d+100); if(p>100)p=100; if(p<0)p=0; printf "%d", p}'; }

PREV_RX=0; PREV_TX=0; PREV_NT=0; LAST_GW=""; LAST_DNS=""; LAST_SSID=""
gateway() { if [ "$OS" = "Darwin" ]; then route -n get default 2>/dev/null | awk '/gateway/{print $2}'; else ip route show default 2>/dev/null | awk '{print $3; exit}'; fi; }
dns_servers() {
  if have resolvectl; then resolvectl dns 2>/dev/null | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | paste -sd, -
  elif [ "$OS" = "Darwin" ]; then scutil --dns 2>/dev/null | awk '/nameserver\[/{print $3}' | sort -u | paste -sd, -
  else awk '/^nameserver/{print $2}' /etc/resolv.conf | paste -sd, -; fi
}
sample_net() {
  local rx tx nt
  if [ "$OS" = "Darwin" ]; then
    read -r rx tx <<< "$(netstat -ib 2>/dev/null | awk '$1 ~ /^en/ && $3 ~ /Link/ {r+=$7; t+=$10} END{print r+0, t+0}')"
  else
    read -r rx tx <<< "$(awk -F'[: ]+' 'NR>2 && $2 != "lo" {r+=$3; t+=$11} END{print r+0, t+0}' /proc/net/dev)"
  fi
  nt=$(now_ms)
  local gw dns; gw="$(gateway)"; dns="$(dns_servers)"
  if [ "$PREV_NT" -gt 0 ] && [ "$rx" -ge "$PREV_RX" ] && [ "$nt" -gt "$PREV_NT" ]; then
    emit net "$(awk -v r=$((rx-PREV_RX)) -v t=$((tx-PREV_TX)) -v ms=$((nt-PREV_NT)) 'BEGIN{printf "\"rxKbps\":%.1f,\"txKbps\":%.1f", r*8/ms, t*8/ms}'),\"gateway\":$(jstr "$gw"),\"dns\":$(jstr "$dns")"
    [ -n "$LAST_GW" ] && [ "$gw" != "$LAST_GW" ] && event gateway-change "$LAST_GW → ${gw:-nenhum}"
    [ -n "$LAST_DNS" ] && [ "$dns" != "$LAST_DNS" ] && event dns-change "$LAST_DNS → $dns"
  fi
  PREV_RX=$rx; PREV_TX=$tx; PREV_NT=$nt; LAST_GW="$gw"; LAST_DNS="$dns"
}

sample_procs() {
  local list
  if [ "$OS" = "Darwin" ]; then
    list="$(ps -Aceo pcpu=,rss=,comm= -r 2>/dev/null | head -5 | awk '{c=$1; m=$2; $1=$2=""; sub(/^ +/,""); printf "%s|%s|%s\n", $0, c, m/1024}')"
  else
    local nc; nc=$(cores)
    list="$(top -b -n 2 -d 1 -w 512 2>/dev/null | awk -v nc="$nc" '/^ *PID +USER/{blk++; next} blk==2 && NF>=12 && n<5 {printf "%s|%.1f|%s\n", $12, $9/nc, $1; n++}')"
    list="$(echo "$list" | while IFS='|' read -r n c pid; do [ -z "$n" ] && continue; r=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' '); echo "$n|$c|$(( ${r:-0} / 1024 ))"; done)"
  fi
  [ -z "$list" ] && return
  local top="" sep=""
  while IFS='|' read -r n c m; do
    [ -z "$n" ] && continue
    top="$top$sep{\"n\":$(jstr "$n"),\"cpu\":$(jnum "$c"),\"memMb\":$(jnum "$m")}"; sep=","
  done <<< "$list"
  emit procs "\"top\":[$top]"
}

# ------------------------------------------------------------------ rede: probes

PING_GW_OK=0; PING_GW_N=0; PING_IN_OK=0; PING_IN_N=0
do_ping() { # do_ping <host> <rótulo> <slot>
  local host="$1" label="$2" slot="$3" ok n
  eval "ok=\$PING_${slot}_OK; n=\$PING_${slot}_N"
  [ "$ok" = "0" ] && [ "$n" -ge 3 ] && return
  local o; if [ "$OS" = "Darwin" ]; then o="$(ping -c 4 -i 0.2 -t 5 "$host" 2>/dev/null)"; else o="$(ping -c 4 -i 0.2 -W 2 "$host" 2>/dev/null)"; fi
  local loss rtt jit
  loss="$(echo "$o" | grep -Eo '[0-9.]+% packet loss' | grep -Eo '^[0-9.]+')"
  read -r rtt jit <<< "$(echo "$o" | awk -F'[/ =]+' '/min\/avg\/max/{print $(NF-2), $(NF-1)}')"
  n=$((n+1)); [ -n "$rtt" ] && ok=1
  eval "PING_${slot}_OK=$ok; PING_${slot}_N=$n"
  if [ "$ok" = "0" ]; then [ "$n" -eq 3 ] && event info "$label não responde a ping (ICMP bloqueado?); medição desativada."; return; fi
  emit ping "\"target\":$(jstr "$host"),\"label\":$(jstr "$label"),\"rtt\":$(jnum "$rtt"),\"loss\":$(jnum "${loss:-100}"),\"jitter\":$(jnum "$jit")"
}

do_tcp() { # do_tcp <host> <rótulo>
  have curl || return
  local o; o="$(curl -so /dev/null -k --connect-timeout 4 -m 6 -w '%{time_connect} %{remote_ip}' "https://$1/" 2>/dev/null)"
  local tc ip; read -r tc ip <<< "$o"
  if [ -z "$tc" ] || [ "$(awk -v t="${tc:-0}" 'BEGIN{print (t>0)}')" = "0" ]; then
    emit tcp "\"target\":$(jstr "$1:443"),\"label\":$(jstr "$2"),\"ok\":false"
  else
    emit tcp "\"target\":$(jstr "$1:443"),\"label\":$(jstr "$2"),\"ok\":true,\"ms\":$(awk -v t="$tc" 'BEGIN{printf "%.1f", t*1000}'),\"ip\":$(jstr "$ip")"
  fi
}

do_dns() {
  local a b; a=$(now_ms)
  if [ "$OS" = "Darwin" ]; then dscacheutil -q host -a name "$1" 2>/dev/null | grep -q ip_address; else getent hosts "$1" >/dev/null 2>&1; fi
  local rc=$?; b=$(now_ms)
  if [ $rc -eq 0 ]; then emit dns "\"name\":$(jstr "$1"),\"ok\":true,\"ms\":$((b-a))"; else emit dns "\"name\":$(jstr "$1"),\"ok\":false"; fi
}

do_http() {
  have curl || return
  local o; o="$(curl -s -o /dev/null -m 20 -w '%{http_code} %{time_namelookup} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total}' "$1" 2>/dev/null)"
  local host; host="$(echo "$1" | awk -F/ '{print $3}')"
  echo "$o" | awk -v url="$1" -v label="$host" '
    { code=$1+0; ok=(code>0 && code<500)
      if (!ok) { printf "\"url\":\"%s\",\"label\":\"%s\",\"code\":%d,\"ok\":false\n", url, label, code; exit }
      dns=$2*1000; con=$3*1000; tls=$4*1000; tt=$5*1000; tot=$6*1000
      tcp=con-dns; if (tcp<0) tcp=0; tl=(tls>0? tls-con : 0); if (tl<0) tl=0
      printf "\"url\":\"%s\",\"label\":\"%s\",\"code\":%d,\"ok\":true,\"dns\":%.1f,\"tcp\":%.1f,\"tls\":%.1f,\"ttfb\":%.1f,\"total\":%.1f\n", url, label, code, dns, tcp, tl, tt, tot }' \
  | { read -r f; [ -n "$f" ] && emit http "$f"; }
}

do_trace() {
  local host="$1" o hops="" sep=""
  if have tracepath && [ "$OS" != "Darwin" ]; then
    o="$(tracepath -n -m 20 "$host" 2>/dev/null | awk '/^ *[0-9]+[?:]/ {ttl=$1; sub(/[?:].*/,"",ttl); ip=$2; rtt=""; for(i=3;i<=NF;i++) if ($i ~ /ms$/) {rtt=$i; sub("ms","",rtt); break}; if (ip=="no") ip="*"; if (!(ttl in seen)) {seen[ttl]=1; print ttl, ip, rtt}}')"
  elif have traceroute; then
    o="$(traceroute -n -q 1 -w 1 -m 20 "$host" 2>/dev/null | awk 'NR>1 {print $1, $2, ($3==""?"":$3)}')"
  else return; fi
  while read -r ttl ip rtt; do
    [ -z "$ttl" ] && continue
    hops="$hops$sep{\"ttl\":$(jnum "$ttl"),\"ip\":$(jstr "${ip:-*}"),\"rtt\":$(jnum "$rtt")}"; sep=","
  done <<< "$o"
  [ -n "$hops" ] && emit trace "\"target\":$(jstr "$host"),\"hops\":[$hops]"
}

LAST_NS=""
do_nsclient() {
  local nsd=/opt/netskope/stagent/nsdiag
  [ "$OS" = "Darwin" ] && nsd="/Library/Application Support/Netskope/STAgent/nsdiag"
  [ -x "$nsd" ] || return
  local s; s="$("$nsd" -f 2>/dev/null | grep -iE 'status|gateway|tunnel' | head -8 | tr '\n' ';' | cut -c1-300)"
  [ -n "$s" ] && [ "$s" != "$LAST_NS" ] && event nsclient "$s"
  LAST_NS="$s"
}

probes() {
  local gw; gw="$(gateway)"
  [ -n "$gw" ] && do_ping "$gw" "Gateway local" GW
  do_ping 8.8.8.8 "Internet (8.8.8.8)" IN
  if [ -n "$TENANT" ]; then do_tcp "gateway-$TENANT.goskope.com" "POP Internet"; do_dns "addon-$TENANT.goskope.com"; else do_dns "www.microsoft.com"; fi
  do_tcp "gateway.npa.goskope.com" "POP Private Access"
  for u in "${URLS[@]}"; do do_http "$u"; done
}

# ------------------------------------------------------------------ laço principal

STOP=0
trap 'STOP=1' INT TERM
event collector-start "intervalo ${INTERVAL}s ($OS)"
echo "Coletando em $OUT (Ctrl+C para parar)…" >&2
START=$(date +%s); LAST_PROBE=0; LAST_TRACE=0; LAST_DISK=0; LAST_NSC=0
sample_cpu; sample_net
sleep 2
while [ $STOP -eq 0 ]; do
  NOW=$(date +%s)
  sample_cpu; sample_mem; sample_battery; sample_net; sample_procs; sample_wifi
  if [ $((NOW-LAST_DISK)) -ge 300 ]; then LAST_DISK=$NOW; sample_disk; fi
  if [ $((NOW-LAST_PROBE)) -ge "$PROBE" ]; then LAST_PROBE=$NOW; probes; fi
  if [ $((NOW-LAST_NSC)) -ge 300 ]; then LAST_NSC=$NOW; do_nsclient; fi
  if [ $((NOW-LAST_TRACE)) -ge $((TRACE_MIN*60)) ]; then
    LAST_TRACE=$NOW
    if [ -n "$TENANT" ]; then do_trace "gateway-$TENANT.goskope.com"; else do_trace "gateway.npa.goskope.com"; fi
  fi
  if [ "$DURATION" -gt 0 ] && [ $(( $(date +%s) - START )) -ge $((DURATION*60)) ]; then break; fi
  ELAPSED=$(( $(date +%s) - NOW )); W=$((INTERVAL-ELAPSED)); [ $W -lt 1 ] && W=1
  for _ in $(seq 1 "$W"); do [ $STOP -eq 1 ] && break; sleep 1; done
done
event collector-stop ""
echo "Arquivo: $FILE" >&2
