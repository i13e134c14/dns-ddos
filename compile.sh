gcc -o dns_amp dns.c -pthread -lm
gcc -o ntp_amp ntp.c -pthread -lm
gcc -o cldap_amp cldap.c -pthread -lm
gcc -o ard_amp ard.c -pthread -lm
gcc -o wsd_amp wsd.c -pthread -lm
gcc -o dvr_amp dvr.c -pthread -lm
gcc -o tcp_bgp tcpbgp.c -pthread
gcc -o tcp_mb middlebox.c -pthread
gcc -o tcp_syn syn.c -pthread
gcc -o tcp_ack ack.c -pthread
gcc -o tcp_tfo tfo.c -pthread
gcc -o ip_rand ip_rand.c -pthread
gcc -o esp_flood esp.c -pthread
gcc -o gre_flood gre.c -pthread
gcc -o udp_pps udp_pps.c -pthread
gcc -o udp_custom udpcustom.c -pthread
rm -rf *.c
clear
