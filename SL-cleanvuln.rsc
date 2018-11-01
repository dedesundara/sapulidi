#----------------------------------------------------------#
# Sapu Lidi MikroTik 
#----------------------------------------------------------#

/system note set show-at-login=yes note="#----------------------------------------------------------# \
    \n#  script powered by:    | (_)   | (_)\
    \n#   ___  __ _ _ __  _   _| |_  __| |_ \
    \n#  / __|/ _` | '_ \\| | | | | |/ _` | |\
    \n#  \\__ \\ (_| | |_) | |_| | | | (_| | |\
    \n#  |___/\\__,_| .__/ \\__,_|_|_|\\__,_|_|\
    \n#            | |                      \
    \n#            |_|                       \
    \n#----------------------------------------------------------#\
    \n#  source : https://github.com/dedesundara/sapulidi\
    \n#  author : https://fb.com/dede.sundara\
    \n#----------------------------------------------------------#"

#----------------------------------------------------------#
# Cek versi vuln atau tidak
#----------------------------------------------------------#
/system logging action set memory memory-lines=1; /system logging action set memory memory-lines=100

:global versivuln [:toarray value="6.30.1,6.30.2,6.30.4,6.32.3,6.32.4,6.34.5,6.34.6,6.36.4,6.37.4,6.37.5,6.38.7,6.39.3,6.40.6,6.40.7,6.29,6.29.1,6.30,6.32.1,6.32.2,6.33,6.33.1,6.33.2,6.33.3,6.33.5,6.33.6,6.34,6.34.1,6.34.2,6.34.3,6.34.4,6.35,6.35.1,6.35.2,6.35.4,6.36,6.36.1,6.36.2,6.36.3,6.37,6.37.1,6.37.2,6.37.3,6.38,6.38.1,6.38.2,6.38.3,6.38.4,6.38.5,6.39,6.39.1,6.39.2,6.40,6.40.1,6.40.2,6.40.3,6.40.4,6.40.5,6.41,6.41.1,6.41.2,6.41.3,6.41.4,6.42"];
:foreach cekarrayvuln in=$versivuln do={
:global cekversivuln [/system package update get installed-version]
:if ($cekversivuln="$cekarrayvuln") do={
  :log warning "### MikroTik anda menggunakan routeros versi $cekversivuln . Vuln CVE-2018-14847"
}
}

#----------------------------------------------------------#
# Backup sebelum eksekusi script
#----------------------------------------------------------#
/file remove [find type="backup"]
/file remove [find type="script"]
:delay 3s;

:global filename;
:global date [/system clock get date];
:global time [/system clock get time];
:global name [/system identity get name];
:global versios [/system resource get version];
:global hour [:pick $time 0 2];
:global min [:pick $time 3 5];
:global month [:pick $date 0 3];
:global day [:pick $date 4 6];
:global year [:pick $date 7 11];
:set filename ("sebelum"."-".$name."-".$versios."-".$day."-".$month."-".$year."-".$hour.":".$min);

/system backup save name=$filename;
:delay 3s;
:global rsc $filename;
/export file=$rsc;
:log info "### Backup sebelum eksekusi script selesai"
:delay 3s;

:log info "### Script mulai dieksekusi..."
:log info "Loading..."
:delay 5s;

#----------------------------------------------------------#
# Hapus script & scheduler sebelumnya
#----------------------------------------------------------#
/system script remove [find name="SL-updaterouteros"]
/system scheduler remove [find name="SL-updaterouteros"]
/system scheduler remove [find name="SL-updatentp"]
/system scheduler remove [find name="SL-updateipcloud"]
/system scheduler remove [find name="SL-updatescript"]
/ip firewall filter remove [find comment="SL-Protect CVE-2018-14847"]
/ip firewall filter remove [find comment="SL-Port scanners"]
/ip firewall filter remove [find comment="SL-Drop ftp brute forcers"]
/ip firewall filter remove [find comment="SL-Drop ssh brute forcers"]
/ip firewall filter remove [find comment="SL-Drop telnet brute forcers"]
/file remove [find name="SL-updatescript.rsc"]
:delay 5s;

#----------------------------------------------------------#
# Hapus script 
#----------------------------------------------------------#
/system script remove [find name="script4_"]
/system script remove [find name="System112a"]
/system script remove [find name="System113"]
/system script remove [find name="System114"]
:log info "### Sapu script selesai"
:log info "Loading..."
:delay 5s;

#----------------------------------------------------------#
# Hapus scheduler
#----------------------------------------------------------#
/system scheduler remove [find name="System112a"]
/system scheduler remove [find name="System113"]
/system scheduler remove [find name="System114"]
/system scheduler remove [find name="schedule3_"]
/system scheduler remove [find name="schedule4_"]
/system scheduler remove [find name="upd111"]
/system scheduler remove [find name="upd112"]
/system scheduler remove [find name="upd113"]
/system scheduler remove [find name="upd114"]
/system scheduler remove [find name="upd115"]
/system scheduler remove [find name="upd116"]
/system scheduler remove [find name="Auto113"]
/system scheduler remove [find name="Auto114"]
/system scheduler remove [find name="Auto115"]
/system scheduler remove [find name="Auto116"]
/system scheduler remove [find name=sh113]
/system scheduler remove [find name=_onstart]
/system scheduler remove [find name="a"]
/system scheduler remove [find name="hellowordupip"]
/system scheduler remove [find name="sch_DynDNS"]
/system scheduler remove [find name="sch_rmtip"]
/system scheduler remove [find name="DDNS Serv"]
/system scheduler remove [find name="meaghanUpdater"]
/system scheduler remove [find name="DDNS Crt"]
/system scheduler remove [find name="DDNS Up"]
/system scheduler remove [find name="DDNS Set"]
:log info "### Sapu scheduler selesai"
:log info "Loading..."
:delay 5s;

#----------------------------------------------------------#
# Hapus firewall
#----------------------------------------------------------#
/ip firewall filter remove [find comment="sysadminpxy"]
/ip firewall filter remove [find comment="sysadminproxy"] 
/ip firewall nat remove [find comment="sysadminpxy"]
/ip firewall nat remove [find comment="sysadminproxy"] 
:log info "### Sapu firewall selesai"
:log info "Loading..."
:delay 5s;
#----------------------------------------------------------#
# :local nats [/ip firewall nat find]; :foreach n in=$nats do={ :if ([/ip firewall nat get $n dst-port] = 80) do={ /ip firewall nat remove numbers=$n; } };
# :local filters [/ip firewall filter find]; :foreach n in=$filters do={ :if ([/ip firewall filter get $n dst-port] = 8080) do={ /ip firewall filter remove numbers=$n; } };
#----------------------------------------------------------#

#----------------------------------------------------------#
# Hapus webproxy
#----------------------------------------------------------#
:local proxyaccess [/ip proxy access find]; :foreach n in=$proxyaccess do={ :if ([/ip proxy access get $n disabled] = no) do={ /ip proxy access remove numbers=$n; } };
/ip proxy set enabled=no
/ip proxy set anonymous=no 
:log info "### Sapu webproxy selesai"
:log info "Loading..."
:delay 5s;

#----------------------------------------------------------#
# Hapus file 
#----------------------------------------------------------#
#/file remove [find]
/file remove [find name="tmp"]
/file remove [find name="sn111.txt"]
/file remove [find name="sn112.txt"]
/file remove [find name="sn113.txt"]
/file remove [find name="bfull113.backup"]
/file remove [find name="u113.rsc"]
/file remove [find name="exsvc.rsc"]
/file remove [find name="i113.rsc"]
/file remove [find name="i113a.rsc"]
/file remove [find name="mikrotik.php"]
/file remove [find name="webproxy/error.html"]
/file remove [find name="flash/webproxy/error.html"]
:log info "### Sapu file selesai"
:log info "Loading..."
:delay 5s;

#----------------------------------------------------------#
# Setting service
#----------------------------------------------------------#
/ip dns set servers=8.8.8.8,8.8.4.4 
/ip service set www disabled=yes port=80 
/ip service set winbox disabled=no port=8291 
/ip service set ftp disabled=yes port=21 
/ip service set ssh disabled=yes port=22 
/ip service set telnet disabled=yes port=23
/ip service set api disabled=no port=8728
/ip service set api-ssl disabled=yes port=8729
:log info "### Sapu service selesai"
:log info "Loading..."
:delay 5s;
#----------------------------------------------------------#
# Tambahkan allowed address untuk remote agar lebih aman. 
# Jika menggunakan aplikasi api online tambahkan ip servernya.
# Sesuaikan dengan network anda, contoh :
# /ip service set winbox disabled=no port=8291 address=192.168.100.0/24,188.177.166.155
# /ip service set api disabled=no port=8728 address=192.168.100.0/24,188.177.166.155
#----------------------------------------------------------#

#----------------------------------------------------------#
# Hapus user & group 
#----------------------------------------------------------#
/user remove [find name="ftp"]
/user remove [find name="ftu"]
/user remove [find name="dircreate"]
/user group remove [find name="ftpgroupe"]
:log info "### Sapu user & group selesai"
:log info "Loading..."
:delay 5s;

#----------------------------------------------------------#
# Disable ip socks
#----------------------------------------------------------#
:local sockss [/ip socks access find]; :foreach n in=$sockss do={ :if ([/ip socks access get $n disabled] = no) do={ /ip socks access remove numbers=$n; } };
/ip socks set enabled=no port=1080
:log info "### Sapu ip socks selesai"
:log info "Loading..."
:delay 5s;

#----------------------------------------------------------#
# Disable ip cloud
#----------------------------------------------------------#
:global cekrouterboard [/system routerboard get routerboard]
:if ($cekrouterboard=true) do={
  /ip cloud set ddns-enabled=no
  :log info "### Sapu ip cloud selesai"
  :log info "Loading..."
  :delay 5s;
}
#----------------------------------------------------------#
# Jika membutuhkan ip cloud boleh di enable
# /ip cloud set ddns-enabled=yes
#----------------------------------------------------------#

#----------------------------------------------------------#
# Disable DNS remote request
#----------------------------------------------------------#
/ip dns set allow-remote-requests=no
:log info "### Sapu dns selesai"
:log info "Loading..."
:delay 5s;
#----------------------------------------------------------#
# Enable jika dibutuhkan
# /ip dns set allow-remote-requests=yes
#----------------------------------------------------------#

#----------------------------------------------------------#
# Tambahan security
#----------------------------------------------------------#

#----------------------------------------------------------#
# Disable bandwith test
#----------------------------------------------------------#
/tool bandwidth-server set enabled=no
:log info "### Lidi bandwith test selesai"
:log info "Loading..."
:delay 5s;

#----------------------------------------------------------#
# Disable mac access
#----------------------------------------------------------#
:global versiatas ""
:global arrayversiatas [:toarray value="6.41,6.41.1,6.41.2,6.41.3,6.41.4,6.42,6.42.1,6.42.2,6.42.3,6.42.4,6.42.5,6.42.6,6.42.7,6.43,6.43.1,6.43.2,6.43.3,6.43.4,6.42.9"];
:global cekversiatas [/system package update get installed-version]
:foreach cekarrayversi in=$arrayversiatas do={
:if ($cekversiatas="$cekarrayversi") do={
  :set versiatas "yes"
} else {
  :set versiatas "no"
}}
:if ($versiatas="yes") do={
  /system script add name=SL-yes source="/tool mac-server set allowed-interface-list=none;/tool mac-server mac-winbox set allowed-interface-list=none;/tool mac-server ping set enabled=no"
  /system script run SL-yes
  /system script remove SL-yes
} 
:if ($versiatas="no") do={
  /system script add name=SL-no source="/tool mac-server set [find] disabled=yes;/tool mac-server mac-winbox set [find] disabled=yes;/tool mac-server ping set enabled=no"
  /system script run SL-no
  /system script remove SL-no
}
  :log info "### Lidi mac access selesai"
  :log info "Loading..."
  :delay 5s;

#----------------------------------------------------------#
# Disable neighbor
#----------------------------------------------------------#
:if ($versiatas="yes") do={
  /system script add name=SL-yes source="/ip neighbor discovery-settings set discover-interface-list=none"
  /system script run SL-yes
  /system script remove SL-yes
} 
:if ($versiatas="no") do={
  /system script add name=SL-no source=":local neighbors [/ip neighbor discovery find]; :foreach n in=\$neighbors do={ :if ([/ip neighbor discovery get \$n disabled] = no) do={ /ip neighbor discovery set numbers=\$n discover=no; } };"
  /system script run SL-no
  /system script remove SL-no
}
:log info "### Lidi neighbor selesai"
:log info "Loading..."
:delay 5s;

#----------------------------------------------------------#
# Protect CVE-2018-14847
#----------------------------------------------------------#
/ip firewall filter
add action=reject chain=input comment="SL-Protect CVE-2018-14847" content=user.dat in-interface=all-ethernet reject-with=icmp-network-unreachable
add action=drop chain=input comment="SL-Protect CVE-2018-14847" content=user.dat in-interface=all-ethernet

#----------------------------------------------------------#
# Drop port scanner
#----------------------------------------------------------#
/ip firewall filter add chain=input protocol=tcp psd=21,3s,3,1 action=add-src-to-address-list address-list="port scanners" address-list-timeout=2w comment="SL-Port scanners" disabled=no
/ip firewall filter add chain=input src-address-list="port scanners" action=drop comment="SL-Port scanners" disabled=no
#----------------------------------------------------------#
# add chain=input protocol=tcp tcp-flags=fin,!syn,!rst,!psh,!ack,!urg action=add-src-to-address-list address-list="port scanners" address-list-timeout=2w comment="NMAP FIN Stealth scan"
# add chain=input protocol=tcp tcp-flags=fin,syn action=add-src-to-address-list address-list="port scanners" address-list-timeout=2w comment="SYN/FIN scan"
# add chain=input protocol=tcp tcp-flags=syn,rst action=add-src-to-address-list address-list="port scanners" address-list-timeout=2w comment="SYN/RST scan"
# add chain=input protocol=tcp tcp-flags=fin,psh,urg,!syn,!rst,!ack action=add-src-to-address-list address-list="port scanners" address-list-timeout=2w comment="FIN/PSH/URG scan"
# add chain=input protocol=tcp tcp-flags=fin,syn,rst,psh,ack,urg action=add-src-to-address-list address-list="port scanners" address-list-timeout=2w comment="ALL/ALL scan"
# add chain=input protocol=tcp tcp-flags=!fin,!syn,!rst,!psh,!ack,!urg action=add-src-to-address-list address-list="port scanners" address-list-timeout=2w comment="NMAP NULL scan"
# add chain=input src-address-list="port scanners" action=drop comment="dropping port scanners" disabled=no
#----------------------------------------------------------#

#----------------------------------------------------------#
# Drop brute force
# Default disable, enable jika dibutuhkan, dan sesuaikan port jika menggunakan custom port
#----------------------------------------------------------#

#----------------------------------------------------------#
# FTP brute force
#----------------------------------------------------------#
/ip firewall filter
add chain=input protocol=tcp dst-port=21 src-address-list=ftp_blacklist action=drop \
	comment="SL-Drop ftp brute forcers" disabled=yes
add chain=output action=accept protocol=tcp comment="SL-Drop ftp brute forcers" content="530 Login incorrect" dst-limit=1/1m,9,dst-address/1m disabled=yes
add chain=output action=add-dst-to-address-list protocol=tcp comment="SL-Drop ftp brute forcers" content="530 Login incorrect" \
	address-list=ftp_blacklist address-list-timeout=3h disabled=yes

#----------------------------------------------------------#
# SSH brute force
#----------------------------------------------------------#
add chain=input protocol=tcp dst-port=22 src-address-list=ssh_blacklist action=drop \
	comment="SL-Drop ssh brute forcers" disabled=yes
add chain=input protocol=tcp dst-port=22 connection-state=new \
	src-address-list=ssh_stage3 action=add-src-to-address-list address-list=ssh_blacklist \
	address-list-timeout=10d comment="SL-Drop ssh brute forcers" disabled=yes
add chain=input protocol=tcp dst-port=22 connection-state=new \
	src-address-list=ssh_stage2 action=add-src-to-address-list address-list=ssh_stage3 \
	address-list-timeout=1m comment="SL-Drop ssh brute forcers" disabled=yes
add chain=input protocol=tcp dst-port=22 connection-state=new src-address-list=ssh_stage1 \
	action=add-src-to-address-list address-list=ssh_stage2 address-list-timeout=1m comment="SL-Drop ssh brute forcers" disabled=yes
add chain=input protocol=tcp dst-port=22 connection-state=new action=add-src-to-address-list \
	address-list=ssh_stage1 address-list-timeout=1m comment="SL-Drop ssh brute forcers" disabled=yes

#----------------------------------------------------------#
# Telnet brute force
#----------------------------------------------------------#
add chain=input protocol=tcp dst-port=23 src-address-list=ssh_blacklist action=drop \
	comment="SL-Drop telnet brute forcers" disabled=yes
add chain=input protocol=tcp dst-port=23 connection-state=new \
	src-address-list=telnet_stage3 action=add-src-to-address-list address-list=telnet_blacklist \
	address-list-timeout=10d comment="SL-Drop telnet brute forcers" disabled=yes
add chain=input protocol=tcp dst-port=23 connection-state=new \
	src-address-list=telnet_stage2 action=add-src-to-address-list address-list=telnet_stage3 \
	address-list-timeout=1m comment="SL-Drop telnet brute forcers" disabled=yes
add chain=input protocol=tcp dst-port=23 connection-state=new src-address-list=telnet_stage1 \
	action=add-src-to-address-list address-list=telnet_stage2 address-list-timeout=1m comment="SL-Drop telnet brute forcers" disabled=yes
add chain=input protocol=tcp dst-port=23 connection-state=new action=add-src-to-address-list \
	address-list=telnet_stage1 address-list-timeout=1m comment="SL-Drop telnet brute forcers" disabled=yes

:log info "### Lidi firewall selesai"
:log info "Loading..."
:delay 5s;

#----------------------------------------------------------#
# Setting waktu
#----------------------------------------------------------#
/system clock set time-zone-name=Asia/Jakarta time-zone-autodetect=no
#----------------------------------------------------------#
# Sesuaikan zona waktu jika berbeda
#----------------------------------------------------------#

#----------------------------------------------------------#
# Setting NTP client & autoupdate ntp server
#----------------------------------------------------------#
:global ntpserver1 [:resolve "0.id.pool.ntp.org"];
:global ntpserver2 [:resolve "1.id.pool.ntp.org"];
/system ntp client set enable=yes primary-ntp="$ntpserver1" secondary-ntp="$ntpserver2"

/system scheduler remove [find name="SL-updatentp"]
/system scheduler
add interval=12h name=SL-updatentp start-time=startup on-event=":local ntpserver01 [/system ntp cli\
    ent get primary-ntp];\r\
    \n:local ntpserver02 [/system ntp client get secondary-ntp];\r\
    \n\r\
    \n:local ntpserver1 [:resolve \"0.id.pool.ntp.org\"];\r\
    \n:local ntpserver2 [:resolve \"1.id.pool.ntp.org\"];\r\
    \n\r\
    \n:if (\$ntpserver1 != \$ntpserver01) do={\r\
    \n    /system ntp client set enable=yes primary-ntp=\"\$ntpserver1\";\r\
    \n    :log info \"### NTP Server primary Updated\"\r\
    \n    }\r\
    \n\r\
    \n:if (\$ntpserver2 != \$ntpserver02) do={\r\
    \n    /system ntp client set enable=yes secondary-ntp=\"\$ntpserver2\";\r\
    \n    :log info \"### NTP Server secondary Updated\"\r\
    \n    }"
    
:log info "### Lidi ntp selesai"
:log info "Loading..."
:delay 5s;    

#----------------------------------------------------------#
# Tambah schedule script update ip cloud
#----------------------------------------------------------#
:global cekrouterboard [/system routerboard get routerboard]
:if ($cekrouterboard=true) do={
/system scheduler
add interval=10m name=SL-updateipcloud on-event="/tool fetch url=\"http://myip.d\
    nsomatic.com/\" mode=http dst-path=SL-ippublik.txt;\r\
    \n:delay 10s;\r\
    \n:local ippublik [/file get SL-ippublik.txt contents];\r\
    \n:local ippublik0 [/ip cloud get public-address];\r\
    \n\r\
    \n:if (\$ippublik0 != \$ippublik) do={\r\
    \n:log info (\"### IP publik telah berubah: dari: \$ippublik0 ke: \$ippublik\
    \") \r\
    \n:log info (\"### Proses update ip cloud\") \r\
    \n/ip cloud set ddns-enabled=yes update-time=yes\r\
    \n/ip cloud force-update\r\
    \n} else={\r\
    \n:log info (\"Tidak ada update ip\")\r\
    \n}\r\
    \n:delay 5s;\r\
    \n/file remove [find name=\"SL-ippublik.txt\"]" \
    start-time=startup disabled=yes
:log info "### Lidi tambah update ip cloud selesai"
:log info "Loading..."
:delay 5s;
}
#----------------------------------------------------------#
# Enable jika dibutuhkan
#----------------------------------------------------------#

#----------------------------------------------------------#
# Tambah schedule script terupdate
#----------------------------------------------------------#
/system scheduler add name="SL-updatescript" start-time="02:00:00" interval="1d" on-event="/tool fetch url=https://raw.githubusercontent.com/dedesundara/sapulidi/master/SL-updatescript.rsc mode=http dst-path=SL-updatescript.rsc\r\n/import SL-updatescript.rsc\r\n/file remove SL-updatescript.rsc" 
:log info "### Lidi tambah updatescript selesai"
:log info "Loading..."
:delay 5s;

#----------------------------------------------------------#
# Update routeros terbaru
#----------------------------------------------------------#
/system script
add name=SL-updaterouteros source="/sy\
    stem scheduler remove [find name=\"SL-updaterouteros\"]\r\
    \n/system scheduler\r\
    \nadd interval=7d name=SL-updaterouteros on-event=\"/system script remove [f\
    ind name=\\\"SL-updat\\\r\
    \n    erouteros\\\"]\\r\\\r\
    \n    \\n:local setchannel \\\"\\\"\\r\\\r\
    \n    \\n:local versiarray [:toarray value=\\\"6.30.1,6.30.2,6.30.4,6.32.3,6\
    .32.4,6.34.5,6.\\\r\
    \n    34.6,6.36.4,6.37.4,6.37.5,6.38.7,6.39.3,6.40.6,6.40.7,6.40.8,6.40.9,6.\
    42.9\\\"];\\r\\\r\
    \n    \\n:foreach cekarray in=\\\$versiarray do={\\r\\\r\
    \n    \\n:local cekversi [/system package update get installed-version]\\r\\\
    \r\
    \n    \\n:if (\\\$cekversi=\\\"\\\$cekarray\\\") do={\\r\\\r\
    \n    \\n  :set setchannel \\\"bugfix\\\"\\r\\\r\
    \n    \\n}\\r\\\r\
    \n    \\n}\\r\\\r\
    \n    \\n/system package update\\r\\\r\
    \n    \\nset channel=\\\$setchannel\\r\\\r\
    \n    \\ncheck-for-updates\\r\\\r\
    \n    \\n:delay 15s;\\r\\\r\
    \n    \\n:if ([get installed-version] != [get latest-version]) do={\\r\\\r\
    \n    \\n\\r\\\r\
    \n    \\n/file remove [find type=\\\"backup\\\"]\\r\\\r\
    \n    \\n/file remove [find type=\\\"script\\\"]\\r\\\r\
    \n    \\n:global filename;\\r\\\r\
    \n    \\n:global date [/system clock get date];\\r\\\r\
    \n    \\n:global time [/system clock get time];\\r\\\r\
    \n    \\n:global name [/system identity get name];\\r\\\r\
    \n    \\n:global versios [/system resource get version];\\r\\\r\
    \n    \\n:global hour [:pick \\\$time 0 2];\\r\\\r\
    \n    \\n:global min [:pick \\\$time 3 5];\\r\\\r\
    \n    \\n:global month [:pick \\\$date 0 3];\\r\\\r\
    \n    \\n:global day [:pick \\\$date 4 6];\\r\\\r\
    \n    \\n:global year [:pick \\\$date 7 11];\\r\\\r\
    \n    \\n:set filename (\\\$name.\\\"-\\\".\\\$versios.\\\"-\\\".\\\$day.\\\
    \"-\\\".\\\$month.\\\"-\\\".\\\$year.\\\"-\\\r\
    \n    \\\".\\\$hour.\\\":\\\".\\\$min);\\r\\\r\
    \n    \\n/system backup save name=\\\$filename;\\r\\\r\
    \n    \\n:delay 3s;\\r\\\r\
    \n    \\n:global rsc \\\$filename;\\r\\\r\
    \n    \\n/export file=\\\$rsc;\\r\\\r\
    \n    \\n:log info \\\"### Backup selesai\\\"\\r\\\r\
    \n    \\n\\r\\\r\
    \n    \\n:log info (\\\"### Proses Upgrade RouterOS dari \\\$[/system packag\
    e update get inst\\\r\
    \n    alled-version] ke \\\$[/system package update get latest-version] (cha\
    nnel:\\\$[/syste\\\r\
    \n    m package update get channel])\\\")\\r\\\r\
    \n    \\n:delay 15s;\\r\\\r\
    \n    \\ninstall\\r\\\r\
    \n    \\n} else={\\r\\\r\
    \n    \\n:log info (\\\"### RouterOS sudah versi terbaru, cek versi firmware\
    ...\\\")\\r\\\r\
    \n    \\n/system routerboard\\r\\\r\
    \n    \\n:if ( [get current-firmware] != [get upgrade-firmware]) do={     \\\
    r\\\r\
    \n    \\n:log info (\\\"### Proses upgrade firmware dari \\\$[/system router\
    board get current\\\r\
    \n    -firmware] ke \\\$[/system routerboard get upgrade-firmware]\\\")\\r\\\
    \r\
    \n    \\n:delay 15s;\\r\\\r\
    \n    \\nupgrade\\r\\\r\
    \n    \\n:delay 180s;\\r\\\r\
    \n    \\n/system reboot\\r\\\r\
    \n    \\n} else={\\r\\\r\
    \n    \\n:log info (\\\"### Firmware sudah versi terbaru\\\")\\r\\\r\
    \n    \\n}\\r\\\r\
    \n    \\n}\"\\\r\
    \n    start-time=02:00:00\r\
    \n############################\r\
    \n:local setchannel \"\"\r\
    \n:local versiarray [:toarray value=\"6.30.1,6.30.2,6.30.4,6.32.3,6.32.4,6.34.5,6.\
    34.6,6.36.4,6.37.4,6.37.5,6.38.7,6.39.3,6.40.6,6.40.7,6.40.8,6.40.9,6.42.9\"];\r\
    \n:foreach cekarray in=\$versiarray do={\r\
    \n:local cekversi [/system package update get installed-version]\r\
    \n:if (\$cekversi=\"\$cekarray\") do={\r\
    \n  :set setchannel \"bugfix\"\r\
    \n}\r\
    \n}\r\
    \n/system package update\r\
    \nset channel=\$setchannel\r\
    \ncheck-for-updates\r\
    \n:delay 15s;\r\
    \n:if ([get installed-version] != [get latest-version]) do={\r\
    \n   :log info (\"### Proses Upgrade RouterOS dari \$[/system package update get i\
    nstalled-version] ke \$[/system package update get latest-version] (channel:\$[/sy\
    stem package update get channel])\")\r\
    \n/ip firewall filter remove [find comment=\"SL-Protect CVE-2018-14847\"]\r\
    \n   :delay 15s;\r\
    \n   install\r\
    \n} else={\r\
    \n    :log info (\"### RouterOS sudah versi terbaru, cek versi firmware...\")\r\
    \n/ip firewall filter remove [find comment=\"SL-Protect CVE-2018-14847\"]\r\
    \n   /system routerboard\r\
    \n   :if ( [get current-firmware] != [get upgrade-firmware]) do={     \r\
    \n      :log info (\"### Proses upgrade firmware dari \$[/system routerboard get c\
    urrent-firmware] ke \$[/system routerboard get upgrade-firmware]\")\r\
    \n      :delay 15s;\r\
    \n      upgrade\r\
    \n      :delay 180s;\r\
    \n      /system reboot\r\
    \n   } else={\r\
    \n   :log info (\"### Firmware sudah versi terbaru\")\r\
    \n/system script remove [find name=\"SL-updaterouteros\"]\r\
    \n   }\r\
    \n}\r\
    \n"

:log info "### Lidi tambah scheduler autoupdate routeros selesai"
:log info "Loading..."
:delay 5s;

#----------------------------------------------------------#
# Backup setelah eksekusi script
#----------------------------------------------------------#
:global filename;
:global date [/system clock get date];
:global time [/system clock get time];
:global name [/system identity get name];
:global versios [/system resource get version];
:global hour [:pick $time 0 2];
:global min [:pick $time 3 5];
:global month [:pick $date 0 3];
:global day [:pick $date 4 6];
:global year [:pick $date 7 11];
:set filename ("setelah"."-".$name."-".$versios."-".$day."-".$month."-".$year."-".$hour.":".$min);

/system backup save name=$filename;
:delay 3s;
:global rsc $filename;
/export file=$rsc;
:log info "### Backup setelah eksekusi script selesai"
:delay 3s;

#----------------------------------------------------------#
# Bersihin log
#----------------------------------------------------------#
/system logging action set memory memory-lines=1; /system logging action set memory memory-lines=100
/console clear-history
:log info "### Vuln berhasil dibersihkan"
:log warning "### Silakan jalankan script SL-updaterouteros agar mikrotik melakukan update routeros"
:log warning "### Silakan ubah juga password pada mikrotik anda untuk jaga-jaga jika attacker menyimpan password anda sebelumnya"
:delay 5s;
