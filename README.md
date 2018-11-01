# sapulidi

Sapulidi adalah script untuk membersihkan script berbahaya dari attacker yang menyerang mikrotik menggunakan vulnerability CVE-2018-14847 di routerOS.

Versions affected:

* Affected all bugfix releases from 6.30.1 to 6.40.7, fixed in 6.40.8 on 2018-Apr-23
* Affected all current releases from 6.29 to 6.42, fixed in 6.42.1 on 2018-Apr-23
* Affected all RC releases from 6.29rc1 to 6.43rc3, fixed in 6.43rc4 on on 2018-Apr-23

## Cara penggunaan script :
1. copy script dibawah ini lalu pastekan di terminal mikrotik

/tool fetch url="https://github.com/dedesundara/sapulidi/blob/master/SL-cleanvuln.rsc" dst-path=SL-cleanvuln.rsc;
/import SL-cleanvuln.rsc;
/file remove SL-cleanvuln.rsc;

2. untuk update routeros jalankan script SL-updaterouteros, atau copy paste script dibawah ini 

3. silakan ubah juga password pada mikrotik anda untuk jaga-jaga jika attacker menyimpan password anda sebelumnya
4. cek kembali settingan mikrotik anda, jika membutuhkan service yang telah di disable oleh script ini anda boleh enable kembali

### Tips :
* #### Tambahkan allowed address untuk remote menggunakan winbox agar lebih aman. 
* /ip service set winbox disabled=no port=8291 address=192.168.100.0/24,188.177.166.155
* #### Jika menggunakan aplikasi api online tambahkan ip servernya.
* /ip service set api disabled=no port=8728 address=192.168.100.0/24,188.177.166.155
* Sesuaikan dengan network anda,



### Fitur sapulidi :
* backup sebelum dan setelah eksekusi script
* penghapusan script, scheduler, firewall, proxy, file, user & group,  
* setting service, ip socks, ip cloud, dns, bandwith test, mac access, neighbor
#### Tambahan script :
* firewall protect CVE-2018-14847, port scanning
* firewall bruteforce (enable dan sesuaikan port jika anda mengubah service port seperti telnet,ssh,ftp)
* scheduler update ntp server
* scheduler update ip cloud
* scheduler update routeros
* scheduler update script terbaru sapulidi

#### Jika ada masalah pada saat menjalankan script atau ada info script terbaru yang belum ada di script ini, atau ada masukan lainnya untuk script ini bisa kontak saya di fb :
* https://fb.com/dede.sundara

#### Thanks to :
* https://fb.com/arsallan.syakib.jawas
* https://fb.com/buananet.pangkalanbun
* https://forum.mikrotik.com dan Semua Forum Diskusi Mikrotik Indonesia
