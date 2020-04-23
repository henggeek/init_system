#!/bin/bash
# auther jimmy_xuli
# Date 2019-05-29

# exit
#set -e

# ctrl+c
trap "Error" SIGINT SIGQUIT

# Global_variables

    # run root
    if [[ "$(whoami)" != 'root' ]];then
        echoRed "please run this script as root" ;exit 1
    fi

    # ANSI Colors
    echoRed() { echo $'\e[0;31m'"$1"$'\e[0m'; }
    echoGreen() { echo $'\e[0;32m'"$1"$'\e[0m'; }
    echoYellow() { echo $'\e[0;33m'"$1"$'\e[0m'; }



# clean_path
rm -rf /tmp/*

# url
download_url=http://218.17.240.187:58888


# create_dir
mkdir -p /data/{soft,appdir,datadir,logs,www,scripts,backups} 

# config_yum_repo
yum_repo(){
	wget -V &> /dev/null || yum -y install wget
	wget -O /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/epel-7.repo
	mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.backup
	wget -O /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo && \
	sed -i -e '/mirrors.cloud.aliyuncs.com/d' -e '/mirrors.aliyuncs.com/d' /etc/yum.repos.d/CentOS-Base.repo
	echoGreen "yum源配置完成..."
}

# systyem_pkg
redhat_pkg() {
	# 安装工具包
	yum -y install mlocate screen ntp unzip zip parted  tree vim lrzsz tcpdump telnet sysstat lsof strace iptraf iotop hdparm nc mtr lrzsz \
	nmap telnet tree ntpdate bash-completion chrony net-tools   htop
	# 安装开发包
	yum -y install gcc gcc-c++ autoconf automake make cmake libevent libtool libXaw expat-devel libxml2-devel libevent-devel ncurses-devel\
	asciidoc cyrus-sasl-devel cyrus-sasl-gssapi krb5-devel libtidy libxslt-devel python-devel openssl-devel gmp-devel snappy snappy-devel libcurl libcurl-devel  gd gd-devel git 
	echoGreen "工具包和开发包已安装完成....."
}

# security_config 
security_env(){
	# ssh_config
	# 加密算法
    grep -E "Ciphers\s" /etc/ssh/sshd_config && sed -ri 's/.*Ciphers.*/Ciphers aes128-ctr,aes192-ctr,aes256-ctr/g' /etc/ssh/sshd_config || \
    echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >>/etc/ssh/sshd_config

    grep -E "MACs\s" /etc/ssh/sshd_config && sed -ri 's/.*MACs.*/MACs hmac-sha1,hmac-ripemd160/g' /etc/ssh/sshd_config || \
    echo "MACs hmac-sha1,hmac-ripemd160" >>/etc/ssh/sshd_config

    # ssh配置
    sed -ri 's/#?GSSAPIAuthentication.*/GSSAPIAuthentication no/' /etc/ssh/sshd_config   
    sed -ri '/#?UseDNS\s+yes/a\UseDNS no' /etc/ssh/sshd_config
    sed -ri 's/#Port 22/Port 23451/g' /etc/ssh/sshd_config                            
    #sed -ri 's/PermitRootLogin\s+yes/PermitRootLogin no/g' /etc/ssh/sshd_config        
    #sed -ri 's/PasswordAuthentication\s+yes/PasswordAuthentication no/g' /etc/ssh/sshd_config  
    systemctl enable sshd && systemctl restart sshd

	 lock_user=(
    `grep -oP "^[a-zA-Z]+(-[a-zA-Z]+)?(?=\:)" /etc/passwd |grep -Ev "root|ops|jenkins|dev|dev-manage|www|qa|ziztour"`
    )

    for user in ${lock_user[@]} ;do
        passwd -l ${user}
    done


	# password策略
	    # passwd
    # sed -ri 's/PASS_MAX_DAYS\s+[0-9]+/PASS_MAX_DAYS   90/g' /etc/login.defs

    # if [ -f /etc/pam.d/common-password ] ;then
    #     grep pam_cracklib.so /etc/pam.d/common-password && \
    #     sed -ri 's/pam_cracklib.so.*/pam_cracklib.so retry=5 minlen=8 difok=3 ucredit=-1 lcredit=-2 dcredit=-1 ocredit=-1/g' /etc/pam.d/common-password || \
    #     echo "password        requisite                       pam_cracklib.so retry=5 minlen=8 difok=3 ucredit=-1 lcredit=-2 dcredit=-1 ocredit=-1" >>/etc/pam.d/common-password
    # fi

    # if [ -f /etc/pam.d/system-auth ] ;then
    #     grep pam_cracklib.so /etc/pam.d/system-auth && \
    #     sed -ri 's/pam_cracklib.so.*/pam_cracklib.so retry=5 minlen=8 difok=3 ucredit=-1 lcredit=-2 dcredit=-1 ocredit=-1/g' /etc/pam.d/system-auth || \
    #     echo "password    requisite     pam_cracklib.so retry=5 minlen=8 difok=3 ucredit=-1 lcredit=-2 dcredit=-1 ocredit=-1" >>/etc/pam.d/system-auth
    # fi

 # 系统用户每月更改密码，root用户使用jenkins统一更改
    cat >/data/scripts/chpasswd.sh<<-EOF
#!/bin/bash
chpasswd_all() {
    shadow_user=(ops jenkins dev dev-manage www qa)

    for user in \${shadow_user[@]} ;do
        echo "\${user}:\`head -c 16 /proc/sys/kernel/random/uuid |base64\`" >> `date +%Y-%m-%d`_passwd.txt |chpasswd
    done
}

case \$1 in
--force|-f)
    chpasswd_all
    ;;
*)
    [ \`date +%d\` -eq 01 ] || exit 1
    chpasswd_all
    ;;
esac
EOF
}


add_user() {
_user_list=(ops jenkins dev dev-manage www qa ziztour)
    # key
    _ops_key='ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCl6VohiSG5/BTb8Uw7T0jmwRzLstLbD8Qxp8rQhWksI0x4Jql4tuWBXZBLEsHb/IOYF6HNGgactN50Z4tdulKu5iUo6HHIyDKfkwBwNQM5IOm62DbvZ690TZC9XiipqSM+iy11YsITMLWSSUWzMBtsoVvw5L5N0smkPPlAz8iHk6SlUasZD3SY9DP8jr3nxNZFWwthj2AmYt7FOltgWVfJDVtmAt+4tKS4rBNF14rP5DjdKYyda6PDOAWIB4QvnYAJUOIEzbj5hXK6dop9ZqpHJus/JUFB1Be7mSSiachjXb5pZ2mrcw0YHQL0fmTusxv45j+KB9bpC8ctyTTpU4Kb'
    _www_key='ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD0MZh8C2QwoutkWR453/MgzFu/KVc3J6dJPCmtBf2kr3wMqsRY53v0wVUKMvpfHC2hxXF8aQsJOdKTYD7PSsPigOGrQcFy1vAj5P/SYXxaPvoIJvmxwZrWc6nC2Lmh5emNwroPCXTUmXINTN0IANrwgnHuNGkTEbLYkN4IJ9bJv3Vs2xwyrRDxEXNzAACJKk+ejaU1Mxhaf+QJombk3FYp/yusVauAsPOq2yTXWm6hflHItNoI6dMQgTd0nbGSKQqwy/XCjgOF8zaQ+uFdTuMjRyF2qOmCVPUH91OiExwt1zOpHLc0lukVG+DGHSf/0hFqayJthc8vZZDFjaa/NyDr'
    _jenkins_key='ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDWTHy0m/lHnkGqexXz2imU5Wc/KXSkmn2m2z6jvnCXy9sPDK1hV4eAySNEErqelp5PO2Is3nqfZktoOdohOmva1k33bACVMMB81Wq8F6JLAsYE9+M/EK2xWTa+VmuIFnNgzsHNQTv7VWLCBLid55BQMqw2wOkkBOpRGnenlz2Ko3bcjAm/Vroa8X4dVHACf6sFZ/21IS+lgVEEh6EoZR76OvI1VxYq2nluJFL7kwnFfUD0vpODzJ0e/hlSDxReI5AKPIbLx8CTCNF0Imwoc+8oWe07Agq7VaLaQY/kNdAIEjwUxJuqDqrL9nz0DlgKHtzJNZQxAA85ZzDY9loJZrWh'
    _dev_key='ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCg6P988SyvEtzkFLYnQcJ0JlMjx/da4apNj7ewDO4FLA5MUvS2lqBwmXz9xkbn8qlfz9vCv8XYUrMcbL14QpYklW2ZXqRA3Ok4kDeP7AtkP09WziZJQGiKF6l2O/YfdDg4tG1CL+cpgPah+H7c7dVOmOlVz1KbF/7ivl00gYpmh4ceNQv2pN0zDrkz0m/c4jZaej7F+ZbsvlmBCbxY1N3vbDwzrXZzT3if5Wi/LB4hjKnBNIhzxa+tu07Oty+8bKDiA6aaNTHzX8F5eaMyvY+nd7v2EidKIeCeKdBbkbYnfHFvoeaCfFcj62bN9dw1M0L4I6LXDtut8Uy7Xwl/itN9'
    _dev_manage_key='ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDAAEIwh0cwO7r6mDBIVMOrDr2T3++PhszFfVHoAAHzr15UPE/loSMDxUV09CNinJa71Wv4Q8DB3ZBj2uHnnsBEs6k2lWQTyP74CA+EV8P2zPbdpHS0vkZkTb+yghfLDS6V9WfTxLqpDv0vkGNaJ+sM7kjBFFtoh0zq+oTxFU07fG23coXVqIByQakeQAIlfm5qHoLpw2WPZBcU3pnP0R/yLASHZAkqWlI1dbn8zCAf5HbowvUX/ZlN8i3sN9uOucZPe3AbY8QUUnKmCMmY6fNb42qKPS++O3s1KqE9RkeSDDqNDiXard/u+CzKgWOROT6R754DNLrrbUn8CbVhwrU3'
    _qa_key='ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4RYBb8N/FCnllYMcWAU0mOmhWM3a3X05yCP3qBND0ky9EjJd/TIqY9RdoxWGYjD0XnmFDZ7Vn7LoP9dM3+ZfjlUHx+J7o648eVXEu5gyycFqcOsnagwMEbksNg2vp8mMWF3/Sw4PngQFSpQ2QS+dGhkNwrulKGJsQR35WWPtUFP6VkQCIAUAdiDP8yrCx/D7ArfDO9dR+hllKGAa31GmLSHsqMMes8TdhPAieW3yDoHlTDl+nwxcaiQrYnyfTsQcdnoTPqZcTUmqSBO6nUtBJ5+N1gwtwi54AwRswIgCUb9Bgzn33iksqXWjanDzkjfLyRaFLBG6OGm4WMvH5QjGl'
    _ziztour_key='ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDTx2RI3nX9GjkY0zyxD3gVNroP4O0qEJwZsAIm889Ui249R9/PXQAJdPP1hsCrKJ0B0/Rl2L1r6K4t8LJ3IubCDCx3E7ufPZSjl7B2x0WhhMiTWpRDRC/c7xWAoocYhPab7oVFossWYiIW8eXs7qynxD9Q89agPcKbfiv0HBK0jmZd1A2x1QqRaGlSOzbub8lKk5is+VQE4S4XtedYpUSV1hOGFsHm14N+irGYolmOeWN0ef4bQNnVb78ZMFfY4aclIMXs7cttRrUq5OwAQGYKpxy764ZduEwbg+6Z16vRMtghd2RCNdoMsDyLYDVcdrFCqXiFfKghxkWXWzkLOGX5'


    # create user
    for _user in ${_user_list[@]} ;do
	    [ x${_user} == x"www" ]  && _auth_key=${_www_key} && _uid=1100
        [ x${_user} == x"ops" ]  && _auth_key=${_ops_key} && _uid=1101
        [ x${_user} == x"jenkins" ]  && _auth_key=${_jenkins_key} && _uid=1102
        [ x${_user} == x"dev" ] &&  _auth_key=${_dev_key} && _uid=1103
        [ x${_user} == x"dev-manage" ]  && _auth_key=${_dev-manage_key} && _uid=1104
        [ x${_user} == x"qa" ]  && _auth_key=${_qa_key} && _uid=1105
        [ x${_user} == x"ziztour" ]  && _auth_key=${_ziztour_key} && _uid=1106
        _user=`echo ${_user} |sed 's/_/-/g'`
        id ${_user} || useradd -m -s /bin/bash -u ${_uid} ${_user}
        [ -d /home/${_user}/.ssh ] || mkdir /home/${_user}/.ssh && chmod 700 /home/${_user}/.ssh
        echo ${_auth_key} > /home/${_user}/.ssh/authorized_keys && chmod 600 /home/${_user}/.ssh/authorized_keys
        chown -R ${_user}.${_user} /home/${_user}
    done

    grep -E "ops.+NOPASSWD.+" /etc/sudoers || echo "ops  ALL=(ALL) NOPASSWD: ALL" >>/etc/sudoers
    grep -E "jenkins.+NOPASSWD.+" /etc/sudoers || echo "jenkins  ALL=(ALL) NOPASSWD: ALL" >>/etc/sudoers
    grep -E "dev-manage.+NOPASSWD.+" /etc/sudoers || echo "dev-manage  ALL=(ALL) NOPASSWD: ALL" >>/etc/sudoers
    
}


kernel_env() {
    cat > /etc/sysctl.conf<<-EOF
# /etc/sysctl.conf - Configuration file for setting system variables
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_retries1 = 2
net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_synack_retries = 3
net.ipv4.tcp_orphan_retries = 0
net.ipv4.tcp_timestamps = 1

net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 6

net.ipv4.tcp_tw_reuse = 0
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_max_tw_buckets = 131072

net.core.netdev_max_backlog = 4096
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.ip_local_port_range = 10000 65535
vm.max_map_count = 524288

net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_window_scaling=1

net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_slow_start_after_idle=0

vm.dirty_ratio = 10
vm.dirty_background_ratio=5
vm.dirty_writeback_centisecs=300
vm.dirty_expire_centisecs = 1500
vm.swappiness = 10
EOF

# clean mem_cache
cat >/data/scripts/mem_cache.sh  <<-EOF
#/bin/bash
use_mem=`free -m|awk 'NR==2'|awk '{print $3}'`
free_mem=`free -m|awk 'NR==2'|awk '{print $4}'`
memlog=/data/logs/memory/mem.log
[ -d /data/logs/memory ]|| mkdir -p /data/logs/memory
echo "===========================================================================" >> \$memlog
date >>\$memlog
if [ \$free_mem -le 2048  ];then
        echo "===============Before============" >> \$memlog
        echo use_mem:\$use_mem >> \$memlog
        echo free_mem:\$free_mem >> \$memlog
        sync && echo 1 >> /proc/sys/vm/drop_caches
else
        echo "Not required" >> \$memlog
fi
exit 1
EOF

    # limit资源配置
cat > /etc/security/limits.conf<<-EOF
* soft nofile 655350
* hard nofile 655350
* soft nproc 204800
* hard nproc 204800
* soft maxlogins 20
* hard maxlogins 20
EOF

	# 关闭防火墙
	systemctl stop firewalld  && systemctl disable firewalld 
	# 开机启动文件权限
	chmod +x /etc/rc.d/rc.local
	# selinux配置
	sed  -i '/^SELINUX=/c SELINUX=disabled' /etc/selinux/config
}


system_env(){
    # welcome
    echo -e "\nWelcome to Ziztour Cloud Elastic Compute Service ! \n" >/etc/motd

    # 同步时间
    ntpdate time1.aliyun.com && hwclock -w

    # 主机名
    echo "localhost" > /etc/hostname

    # 家目录环境
    cat >>/etc/skel/.bashrc<<-EOF
# ~/.bashrc: executed by bash(1) for non-login shells.
[ -f /etc/profile ] && . /etc/profile
EOF
    cp /etc/skel/.bashrc /root/.bashrc

	# 全局环境/etc/profile
	sed -i 's/HISTSIZE=1000/HISTSIZE=5000/g' /etc/profile
    cat >> /etc/profile<<-EOF
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
alias vi='vim'
alias ls='ls --color=auto'
alias ll='ls -al'
alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'
alias untar='tar xvf'
alias grep='grep --color=auto'
alias getpass="openssl rand -base64 20"

SHELL=/bin/bash
HISTFILESIZE=10000
HISTTIMEFORMAT="\$whoami : %F %T : "
HISTCONTROL=ignoredups
IP=\`ip a |grep -oP "\d.*(?=/\d{1,2}\sb.+eth0)"\`
TZ="Asia/Shanghai"
TMOUT=6000
LANG="en_US.UTF-8"
PS1="[\[\e[0;32;1m\]\u\[\e[0m\]@\[\e[0;36;1m\]\h\[\e[0m\] \[\e[0;33;1m\]\W\[\e[0m\]]\\\\$ "
eval "\$(dircolors -b)"
umask 022
export  SHELL HISTSIZE HISTFILESIZE HISTTIMEFORMAT HISTCONTROL WORKID TZ LANG PS1
EOF

# vim优化配置
    cat>/etc/skel/.vimrc<<-EOF
set pastetoggle=<F9>
set nobackup
set noswapfile
set hlsearch
set nonumber
set cindent
set autoindent
set shiftwidth=4
set tabstop=4
set expandtab
set softtabstop=4
set laststatus=2
set ruler
set backspace=indent,eol,start
set vb
set paste
syntax on
EOF
}

crontab_env() {
    # crontab
    cat >/var/spool/cron/root<<-EOF
# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  *   command to be executed

*/30 * * * * /usr/sbin/ntpdate time1.aliyun.com >> /dev/null
#0 2  * * * /bin/sh /data/scripts/mem_cache.sh >> /dev/null
#* *  1 * * /bin/sh /data/scripts/chpasswd.sh >> /dev/null
#0  3  *  *  *   /usr/bin/find /data/logs/ -type f -mtime +60  | /usr/bin/xargs -i rm -rf {}
EOF
}


jdk_env (){
    [ -L /data/appdir/jdk ] && echoRed "检测到jdk已安装，退出安装" && exit 1  
    cd /tmp &&  wget ${download_url}/java/jdk-8u231-linux-x64.tar.gz -O /tmp/jdk-8u231-linux-x64.tar.gz
    tar -xzvf /tmp/jdk-8u231-linux-x64.tar.gz -C /data/appdir && mv  /data/appdir/jdk1.8.0_231 /data/appdir/jdk

cat >> /etc/profile<<-EOF
JAVA_HOME=/data/appdir/jdk
JRE_HOME=/data/appdir/jdk/JRE
CLASS_PATH=.:\$JAVA_HOME/lib/dt.jar:\$JAVE_HOME/lib/tools.jar:\$JRE_HOME/lib
PATH=\$PATH:\$JAVA_HOME/bin:\$JRE_HOME/bin
EOF

source /etc/profile

/data/appdir/jdk/bin/java -version &> /dev/null && echoGreen "已安装完成..." || echoYellow "可能安装有问题，请检查"
rm -rf /tmp/jdk*
}

maven_env(){
    [ -d /data/appdir/maven ] && echoRed "检测到/data/appdir已经安装maven" && exit 1
    wget ${download_url}/maven/apache-maven-3.3.9-bin.tar.gz -O /tmp/apache-maven-3.3.9-bin.tar.gz && cd /tmp
     tar -xzvf /tmp/apache-maven-3.3.9-bin.tar.gz -C /data/appdir/ && mv /data/appdir/apache-maven-3.3.9 /data/appdir/maven
    # sed -i '146a \\t<mirror>\n\t\t<id>nexus-aliyun</id>\n\t\t<name>Nexus aliyun</name>\n\t\t<url>http://maven.aliyun.com/nexus/content/groups/public</url>\n\t</mirror>' \
    # /data/appdir/maven/conf/settings.xml

    echo "PATH=\$PATH:/data/appdir/maven/bin" >> /etc/profile  && source /etc/profile

    /data/appdir/maven/bin/mvn -v &> /dev/null && echoGreen "maven安装完成..." || echoYellow "可能安装有问题，请检查..."
    rm -rf /tmp/maven*
}

tomcat_env() {
    totle_mem=`free -m|grep Mem|awk -F " "  '{print $2}'`
    /data/appdir/jdk/bin/java -version &> /dev/null ||  exit 1
    [ ${totle_mem} -lt 3568 ] && echoRed "检测到内存不足4G，退出安装" && exit 2
    [ -L /data/appdir/apache-tomcat ] && echoRed "检测到/data/appdir/下已经安装了tomcat，退出安装" && rm -rf /tmp/apache-tomcat* && exit 3
    wget ${download_url}/tomcat/apache-tomcat-8.5.31.tar.gz -O /tmp/apache-tomcat-8.5.31.tar.gz
    tar -xzvf /tmp/apache-tomcat-8.5.31.tar.gz -C /data/appdir && mv  /data/appdir/apache-tomcat-8.5.31/ /data/appdir/apache-tomcat

    rm -rf /data/appdir/apache-tomcat/webapps/*
    echo 'JAVA_OPTS="$JAVA_OPTS -Djsse.enableSNIExtension=true -Dfile.encoding=UTF-8 -XX:InitialHeapSize=3568M -XX:MaxHeapSize=3568M -XX:NewSize=512M -XX:+UseParallelGC -XX:+UseParallelOldGC -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/usr/local/apache-tomcat/heapdump.hprof"' >>/data/appdir/apache-tomcat/bin/setenv.sh
        echo 'CATALINA_PID="$CATALINA_BASE/tomcat.pid"'>>/data/appdir/apache-tomcat/bin/setenv.sh
    cd /data/appdir/apache-tomcat/lib
    unzip catalina.jar ; sed -ir 's/8\..*/1.0.0/g' org/apache/catalina/util/ServerInfo.properties
    /data/appdir/jdk/bin/jar uvf catalina.jar org/apache/catalina/util/ServerInfo.properties
    rm -rf META-INF org ;cd ~
    sed -ri '/Connector port="8080"/a\               useSendfile="false" socket.directBuffer="false"' /data/appdir/apache-tomcat/conf/server.xml
    sed -ri '/Connector port="8080"/a\               compression="on" compressableMimeType="text/html,text/xml,text/plain,application/json,application/octet-stream,image/jpeg,image/png,image/bmp,image/gif"' /data/appdir/apache-tomcat/conf/server.xml
    sed -ri '/Connector port="8080"/a\               maxThreads="500" minSpareThreads="20" acceptCount="100"' /data/appdir/apache-tomcat/conf/server.xml

        cat > /lib/systemd/system/tomcat.service<<-EOF
[Unit]
Description=Tomcat
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
Environment="JAVA_HOME=/data/appdir/jdk"
PIDFile=/data/appdir/apache-tomcat/tomcat.pid
ExecStart=/data/appdir/apache-tomcat/bin/startup.sh
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

source  /etc/profile && /data/appdir/apache-tomcat/bin/version.sh &> /dev/bull && echoGreen "Tomcat 已经安装完成...."   || echoYellow "可能安装有问题，请检查"
rm -rf /tmp/tomcat*
}

# openresty install
openresty_env() {
    [ -d /appdir/data/appdir/openresty ] && echoRed "检测到/appdir/data/下已安装openresty，故而退出！" && rm -rf $dir && exit 1
    id www >& /dev/null
    [ $? -ne 0 ] && echo "用户www未不存在,创建www用户..." && /usr/sbin/useradd  www  -u 1100
    wget ${download_url}/openresty/openresty-1.15.8.1.tar.gz -O /tmp/openresty-1.15.8.1.tar.gz
    tar -xzvf /tmp/openresty-1.15.8.1.tar.gz -C /tmp/
    wget ${download_url}/ngx_dynamic_upstream-master/ngx_dynamic_upstream-master.zip -O /tmp/ngx_dynamic_upstream-master.zip
    unzip /tmp/ngx_dynamic_upstream-master.zip -d /tmp/
    cd /tmp/openresty-1.15.8.1
     ./configure --user=www \
                 --group=www \
                 --prefix=/data/appdir/openresty \
                 --with-luajit \
            --with-http_iconv_module \
                 --without-http-cache \
                 --with-http_ssl_module \
                 --with-http_gzip_static_module\
        --with-http_image_filter_module \
        --with-http_realip_module \
        --with-http_stub_status_module \
        --add-module=../ngx_dynamic_upstream-master
        CPU_NUM=$(cat /proc/cpuinfo|grep processor|wc -l)
        if [ $CPU_NUM -gt 1 ];then
        make -j$CPU_NUM
        else
        make
        fi
        make install
    [ -d /data/appdir/openresty/nginx/conf/vhost ] || mkdir /data/appdir/openresty/nginx/conf/vhost

# config
cat >/data/appdir/openresty/nginx/conf/nginx.conf<<-EOF
user  www;
worker_processes  auto;    #nginx工作线程数


error_log  /data/appdir/openresty/nginx/logs/error.log;
pid    /data/appdir/openresty/nginx/conf/nginx.pid;

worker_rlimit_nofile 102400;
events {
    use epoll;
    worker_connections  102400;
}
http {
    include  mime.types;   #设定mime类型
    default_type application/octet-stream;   
        log_format main '\$remote_addr - \$remote_user [\$time_local] [\$request] [\$status] '
                '[\$server_name] [\$body_bytes_sent]  [\$request_length]    [\$http_referer] ' 
                '[\$request_time]  [\$upstream_addr] [\$upstream_status] '
                        '[\$body_bytes_sent] [\$request_length] [\$content_length] [\$http_referer] '
                '[\$http_x_app_version] [\$http_user_agent]';
include /data/appdir/openresty/nginx/conf/proxy.conf;   #反向代理配置文件
include /data/appdir/openresty/nginx/conf/vhost/*.conf;  #虚拟主机配置文件
charset utf8;                      #默认编码
server_tokens off;   #关闭nginx版本号
server_names_hash_bucket_size 128; #服务器名字的哈希存储大小
client_header_buffer_size 32k;   #设定请求缓冲,nginx默认会用client_header_buffer_size这个buffer来读取header值，如果header过大，它会使用large_client_header_buffers来读取
large_client_header_buffers 4 32k;
sendfile on;     #sendfile 指令指定 nginx 是否调用 sendfile 函数（zero copy 方式）来输出文件，对于普通应用，必须设为on。如果用来进行下载等应用磁盘IO重负载应用，可设置为 off，以平衡磁盘与网络IO处理速度，降低系统 uptime。
send_timeout 60;  #客户端发送内容超时
tcp_nopush on;    #网络连接选择
keepalive_timeout 60;  #指定客户端保活超时时间
tcp_nodelay on;       #网络连接选择
gzip on;  #设置gzip
gzip_min_length 1k;  #最小压缩文件大小
gzip_buffers 4 16k;   #压缩缓冲区
gzip_http_version 1.0;  #压缩版本
gzip_comp_level 7;    #压缩比率
gzip_types
    application/atom+xml
    application/javascript
    application/json
    application/rss+xml
    application/vnd.ms-fontobject
    application/x-font-ttf
    application/x-web-app-manifest+json
    application/xhtml+xml
    application/xml
    font/opentype
    image/svg+xml
    image/x-icon
    text/css
    text/plain
    text/x-component; #压缩类型
gzip_vary on;     #vary header支持
set_real_ip_from 100.97.0.0/16;
real_ip_header X-Forwarded-For;
#limit_req_zone  \$binary_remote_addr \$uri zone=one:10m rate=5r/s; #相同的ip地址并且访问相同的uri，会导致进入limit req的限制（每秒5个请求）
#server_info off; #当打开server_info的时候，显示错误页面时会显示URL、服务器名称和出错时间。
#server_tag off; #自定义设置HTTP响应的server头，‘off’可以禁止返回server头。如果什么都不设置，就是返回默认Nginx的标识。
    server {
        listen     80 default_server;
        return    403;
    }
    server {
        listen 18081;
        location /nginx_status {
            stub_status on;
            access_log off;
            allow 172.20.0.0/16;
            deny all;
        }
    }
}

EOF

# vhost proxy
cat >/data/appdir/openresty/nginx/conf/proxy.conf<<-EOF
    proxy_redirect          off;
    proxy_hide_header      Vary;
    proxy_set_header        Accept-Encoding '';
    proxy_set_header        Host            \$host;
    proxy_set_header        X-Real-IP      \$remote_addr;
    proxy_set_header        X-Forwarded-For \$proxy_add_x_forwarded_for;
    client_max_body_size    10m;
    client_body_buffer_size 128k;
    proxy_connect_timeout  120;
    proxy_send_timeout     120;
    proxy_read_timeout      90;
    proxy_buffer_size      4k;
    proxy_buffers          32 4k;
    proxy_busy_buffers_size 64k;
EOF

# vhost agent_deny
cat >/data/appdir/openresty/nginx/conf/agent_deny.conf<<-EOF
    #禁止Scrapy等工具的抓取
    if (\$http_user_agent ~* (Scrapy|Curl|HttpClient)) {
        return 403;
    }
    #禁止指定UA及UA为空的访问
    if (\$http_user_agent ~ "FeedDemon|Indy Library|Alexa Toolbar|AskTbFXTV|AhrefsBot|CrawlDaddy|CoolpadWebkit|Java|Feedly|UniversalFeedParser|ApacheBench|Microsoft URL Control|Swiftbot|ZmEu|oBot|jaunty|Python-urllib|lightDeckReports Bot|YYSpider|DigExt|HttpClient|MJ12bot|heritrix|EasouSpider|Ezooms|^$" ) {
     return 403;             
}   
    #禁止非GET|HEAD|POST方式的抓取
    if (\$request_method !~ ^(GET|HEAD|POST)$) {
           return 403;
    }
EOF

# vhost config
cat >/data/appdir/openresty/nginx/conf/vhost/default.conf<<-EOF
    upstream localhost {
        zone zone_for_localhost 2m;
        server 127.0.0.1:8080 weight=1 max_fails=3 fail_timeout=30s;
    }
    server {
        listen 8000;
        include proxy.conf;
        include agent_deny.conf; 
        location / {
            proxy_pass http://localhost;
        }
    }
EOF

cat > /lib/systemd/system/nginx.service  <<-EOF
    [Unit]
    Description=nginx service
    After=network.target

    [Service]
    Type=forking
    #PIDFile=/data/appdir/openresty/nginx/conf/nginx.pid
    ExecStart=/data/appdir/openresty/nginx/sbin/nginx  -c /data/appdir/openresty/nginx/conf//nginx.conf
    ExecReload=/data/appdir/openresty/nginx/sbin/nginx -s reload
    ExecStop=/data/appdir/openresty/nginx/sbin/nginx -s stop
    PrivateTmp=true

    [Install]
    WantedBy=multi-user.target                                            
EOF

    

    # nginx_path
    echo "PATH=\$PATH:/data/appdir/openresty/nginx/sbin" >> /etc/profile &&　source /etc/profile
    systemctl enable nginx && systemctl start nginx

    ln -s /data/www/ /www && chown www.www /www && ln -s /data/appdir/openresty/nginx/conf /nginx_config
    /data/appdir/openresty/nginx/sbin/nginx -V >> /dev/null && echoGreen "nginx 安装完成....." || echoYellow "可能安装有问题，请检查..."  
    rm -rf /tmp/openrsty* 
}


node_env(){
        [ -d /data/appdir/node ] && echoRed "检测到/data/appdir已经安装node" && exit 1
        cd /tmp/ && wget ${download_url}/nodejs/node-v12.16.1-linux-x64.tar.xz  && tar -xf node-v12.16.1-linux-x64.tar.xz
        mv node-v12.16.1-linux-x64 /data/appdir/node && chown www.www /data/appdir/node -R
        id www >& /dev/null
        [ $? -ne 0 ] && echo "用户www未不存在,创建www用户..." && /usr/sbin/useradd  www  -u 1100
su - www <<EOF
echo "PATH="/data/appdir/node/bin:"\$PATH""" >> ~/.bashrc && source ~/.bashrc
/data/appdir/node/bin/npm install -g cnpm --registry=https://registry.npm.taobao.org
EOF
        [ -d /data/appdir/node ] && echoGreen " nodejs安装完成....." ||  echoYellow "可能安装有问题，请检查！" 
        rm -rf /tmp/node*
}

php_env(){
    [ -d /data/appdir/php ] && echoRed "检测到/data/appdir已经安装php" && exit 1
    id www >& /dev/null
    [ $? -ne 0 ] && echo "用户www未不存在,创建www用户..." && /usr/sbin/useradd  www  -u 1100
    [ -d /appdir/data/appdir/php ] && echoRed "检测到/appdir/data/下已安装php，故而退出！" && rm -rf $dir && exit 1
    yum install -y zlib-devel libxml2-devel libjpeg-turbo-devel libpng-devel gd-devel libiconv-devel freetype-devel libcurl-devel libxslt-devel openssl-devel readline-devel php-mcrypt  libmcrypt  libmcrypt-devel gc
    
    wget ${download_url}/php/libiconv-1.15.tar.gz -O /tmp/libiconv-1.15.tar.gz && cd /tmp
        tar -xf libiconv-1.15.tar.gz &&  cd libiconv-1.15
        ./configure --prefix=/usr/local/libiconv
    make && make install 


    wget ${download_url}/php/php-7.1.13.tar.gz -O /tmp/php-7.1.13.tar.gz && cd /tmp
    tar -xf php-7.1.13.tar.gz && cd php-7.1.13
    ./configure --prefix=/data/appdir/php --with-config-file-path=/data/appdir/php/etc/ --enable-maintainer-zts  --with-curl --with-freetype-dir --with-gd --enable-gd-native-ttf --with-gettext --with-ldap  --with-iconv-dir=/usr/local/libiconv/ --with-kerberos --with-libdir=lib64 --with-libxml-dir --with-mysqli  --with-openssl  --with-pcre-regex  --with-pdo-mysql=mysqlnd  --with-pdo-sqlite --with-pear  --with-jpeg-dir --with-png-dir  --with-xmlrpc --with-xsl --with-zlib --enable-fpm --enable-bcmath --enable-libxml  --enable-inline-optimization --enable-mbregex --enable-mbstring --enable-opcache --enable-pcntl --enable-shmop --enable-soap --enable-sockets --enable-sysvsem --enable-xml --enable-zip --enable-pdo --enable-mysqlnd
    # ./configure --prefix=/data/appdir/php --enable-maintainer-zts  --with-curl --with-freetype-dir --with-gd --enable-gd-native-ttf --with-gettext --with-iconv-dir=/usr/local/libiconv/ --with-kerberos --with-libdir=lib64 --with-libxml-dir --with-mysqli  --with-openssl  --with-pcre-regex  --with-pdo-mysql=mysqlnd  --with-pdo-sqlite --with-pear  --with-jpeg-dir --with-png-dir  --with-xmlrpc --with-xsl --with-zlib --enable-fpm --enable-bcmath --enable-libxml  --enable-inline-optimization --enable-mbregex --enable-mbstring --enable-opcache --enable-pcntl --enable-shmop --enable-soap --enable-sockets --enable-sysvsem --enable-xml --enable-zip --enable-pdo --enable-mysqlnd
    make  && make install
    
# 启动脚本文件
cat >/usr/lib/systemd/system/php-fpm.service<<-EOF
[Unit]
Description=php-fpm
After=network.target

[Service]
Type=forking
ExecStart=/data/appdir/php/sbin/php-fpm
ExecStop=/bin/pkill -9 php-fpm
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# php用户配置
cat >/data/appdir/php/etc/php-fpm.d/www.conf<<-EOF
[global]
pid=/var/run/php-fpm.pid
error_log=/var/1og/php/php-fpm.log
log_level=warning
rlimit_files=655350
events.mechanism=epoll

[www]
user=www
group=www   
listen=127.0.0.1:9000
listen.owner=www
listen.group=www
listen.mode=0660
listen.allowed_clients=127.0.0.1
pm=dynamic 
pm.max_children=512
pm.start_servers=10
pm.min_spare_servers=10
pm.max_spare_servers=30
pm.process_idle_timeout=15s;
pm.max_requests=2048

php_flag[display_errors]=off
php_admin_value[error_log]=/var/1og/php/php-www.log
php_admin_flag[log_errors]=on

request_slowlog_timeout=5s 
slowlog=/var/1og/php/php-slow.log
EOF

    mkdir /var/1og/php/ -p && mv /data/appdir/php/etc/php-fpm.conf.default /data/appdir/php/etc/php-fpm.conf &&  cp /tmp/php-7.1.13/php.ini-development  /data/appdir/php/etc/php.ini
    # 优化php配置文件文件
    sed -i   "s#^expose_php = On#expose_php = Off#g" /data/appdir/php/etc/php.ini
    sed -i   "s#^upload_max_filesize = 2M#upload_max_filesize = 50M#g" /data/appdir/php/etc/php.ini 
    sed -i   "s#^allow_url_fopen = On#allow_url_fopen = Off#g" /data/appdir/php/etc/php.ini 
    sed -i   "s#^;date.timezone =#date.timezone = Asia/Shanghai#g" /data/appdir/php/etc/php.ini 
    sed -i   "s#^;error_log = php_errors.log#error_log = /var/log/php_error.log #g" /data/appdir/php/etc/php.ini 
    sed -i   "/^error_reporting/c error_reporting = E_WARNING \& E_ERROR" /data/appdir/php/etc/php.ini

    # php_path
    echo "PATH=\$PATH:/data/appdir/php/bin/" >> /etc/profile   && /etc/profile
    systemctl enable php-fpm.service && systemctl start php-fpm.service 

    /data/appdir/php/bin/php -v &> /dev/bull && echoGreen "PHP 已经安装完成...."   || echoYellow "可能安装有问题，请检查...."
    rm -rf /tmp/php*
}


mysql_env() {
    [ -d /data/appdir/mysql ] && echoRed "检测到/data/appdir已经安装mysql" && exit 1

    # 判断用户是否存在
    id mysql >& /dev/null
    [ $? -ne 0 ] && echoGreen "用户mysql未不存在,创建mysql用户..." && /usr/sbin/useradd -s /sbin/nologin  mysql 
    # 创建安装目录和数据目录
    mkdir -p /data/appdir/mysql/{data,var} && /bin/chown -R mysql:mysql /data/appdir/mysql

    #编译安装boost
    mkdir -p /usr/local/boost && cd /tmp
    wget ${download_url}/mysql/boost_1_59_0.tar.gz  && tar -xf boost_1_59_0.tar.gz -C /usr/local/boost

   
    #编译安装mysql5.7
    cd /tmp && wget -c ${download_url}/mysql/mysql-5.7.21.tar.gz
    /bin/tar -zxvf mysql-5.7.21.tar.gz
    cd mysql-5.7.21 && /usr/bin/cmake -DCMAKE_INSTALL_PREFIX=/data/appdir/mysql -DMYSQL_DATADIR=/data/appdir/mysql/data -DSYSCONFDIR=/etc -DWITH_MYISAM_STORAGE_ENGINE=1 -DWITH_INNOBASE_STORAGE_ENGINE=1 -DWITH_MEMORY_STORAGE_ENGINE=1 -DWITH_READLINE=1 -DMYSQL_UNIX_ADDR=/data/appdir/mysql/var/mysql.sock  -DMYSQL_TCP_PORT=3306 -DENABLED_LOCAL_INFILE=1 -DWITH_PARTITION_STORAGE_ENGINE=1 -DEXTRA_CHARSETS=all -DDEFAULT_CHARSET=utf8 -DDEFAULT_COLLATION=utf8_general_ci -DWITH_BOOST=/usr/local/boost
    make && make install
   
 
    #执行初始化配置脚本，创建系统自带的数据库和表
    /data/appdir/mysql/bin/mysql_install_db --basedir=/data/appdir/mysql --datadir=/data/appdir/mysql/data --user=mysql

#配置my.cnf
cat > /etc/my.cnf << EOF
    [client]
    port = 3306
    socket = /data/appdir/mysql/var/mysql.sock
       
    [mysqld]
    port = 3306
    socket = /data/appdir/mysql/var/mysql.sock
       
    basedir = /data/appdir/mysql/
    datadir = /data/appdir/mysql/data
    pid-file = /data/appdir/mysql/data/mysql.pid
    user = mysql
    bind-address = 0.0.0.0
    server-id = 1
    sync_binlog=1
    log_bin = mysql-bin
       
    skip-name-resolve
    #skip-networking
    back_log = 600
       
    max_connections = 3000
    max_connect_errors = 3000
    ##open_files_limit = 65535
    table_open_cache = 512
    max_allowed_packet = 16M
    binlog_cache_size = 16M
    max_heap_table_size = 16M
    tmp_table_size = 256M
       
    read_buffer_size = 1024M
    read_rnd_buffer_size = 1024M
    sort_buffer_size = 1024M
    join_buffer_size = 1024M
    key_buffer_size = 8192M
       
    thread_cache_size = 8
       
    query_cache_size = 512M
    query_cache_limit = 1024M
       
    ft_min_word_len = 4
       
    binlog_format = mixed
    expire_logs_days = 30
       
    log-error = /data/appdir/mysql/data/mysql-error.log
    slow_query_log = 1
    long_query_time = 1
    slow_query_log_file = /data/appdir/mysql/data/mysql-slow.log
       
    performance_schema = 0
    explicit_defaults_for_timestamp
       
    ##lower_case_table_names = 1
       
    skip-external-locking
       
    default_storage_engine = InnoDB
    ##default-storage-engine = MyISAM
    innodb_file_per_table = 1
    innodb_open_files = 500
    innodb_buffer_pool_size = 2048M
    innodb_write_io_threads = 1000
    innodb_read_io_threads = 1000
    innodb_thread_concurrency = 8
    innodb_purge_threads = 1
    innodb_flush_log_at_trx_commit = 2
    innodb_log_buffer_size = 4M
    innodb_log_file_size = 32M
    innodb_log_files_in_group = 3
    innodb_max_dirty_pages_pct = 90
    innodb_lock_wait_timeout = 120
       
    bulk_insert_buffer_size = 8M
    myisam_sort_buffer_size = 8M
    myisam_max_sort_file_size = 2G
    myisam_repair_threads = 1
       
    interactive_timeout = 28800
    wait_timeout = 28800
    sql_mode='NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION'
       
    [mysqldump]
    quick
    max_allowed_packet = 16M
       
    [myisamchk]
    key_buffer_size = 8M
    sort_buffer_size = 8M
    read_buffer = 4M
    write_buffer = 4M
       
    port = 3306
EOF

    # 配置启动服务脚本文件
    cp /data/appdir/mysql/support-files/mysql.server /etc/init.d/mysqld


    #创建sock链接
    mkdir -p /var/lib/mysql && ln -s /data/appdir/mysql/var/mysql.sock /var/lib/mysql/mysql.sock

    # 添加环境变量
    echo "PATH=\$PATH:/data/appdir/mysql/bin/" >> /etc/profile && source  /etc/profile

    /data/appdir/mysql/bin/mysql -V &>/dev/null && echoGreen "mysql已安装完成...." || echo Yellow "可能安装有问题,请检查...."
}

zibbix_agentd_env() {
    zabbixserver= 192.168.8.4
    zabbix_agentd -V &> /dev/null && echoRed "检测到系统中有zabbix-agentd命令，故而退出！"  && exit 1
    cd /tmp && wget ${download_url}/zabbix/zabbix-agent-4.2.8-1.el7.x86_64.rpm && yum -y install zabbix-agent-4.2.8-1.el7.x86_64.rpm
    # 修改配置文件
    sed -i "s/^Server=.*/Server=$zabbixserver/g"  /etc/zabbix/zabbix_agentd.conf
    sed -i "s/^ServerActive=.*/ServerActive=$zabbixserver/g"  /etc/zabbix/zabbix_agentd.conf
    sed -i "s/^Hostname=.*/Hostname=$(hostname -I)/g"  /etc/zabbix/zabbix_agentd.conf
    systemctl enable zabbix-agent && systemctl restart zabbix-agent
    rm -rf /tmp/zabbix*
}

supervisor_env() {
    which supervisorctl &>/dev/null &&  echoRed "检测到系统supervisorctl中有命令，故而退出！"  && exit 1
    yum -y install python-meld3 && cd /tmp/ && wget  ${download_url}/supervisor/supervisor-3.4.0-1.el7.noarch.rpm && yum -y install  supervisor-3.4.0-1.el7.noarch.rpm 
    cat >/etc/supervisord.conf<<-EOF
[unix_http_server]
file=/var/run/supervisor.sock   ; (the path to the socket file)
chmod=0700                 ; socket file mode (default 0700)
username=ziztour              ; (default is no username (open server))
password=ziz123321               ; (default is no password (open server))
[inet_http_server]         ; inet (TCP) server disabled by default
port=*:9001        ; (ip_address:port specifier, *:port for all iface)
username=ziztour              ; (default is no username (open server))
password=ziz123321               ; (default is no password (open server))
[supervisord]
logfile=/tmp/supervisord.log ; (main log file;default i\$CWD/supervisord.log)
logfile_maxbytes=50MB        ; (max main logfile bytes b4 rotation;default 50MB)
logfile_backups=10           ; (num of main logfile rotation backups;default 10)
loglevel=info                ; (log level;default info; others: debug,warn,trace)
pidfile=/tmp/supervisord.pid ; (supervisord pidfile;default supervisord.pid)
nodaemon=false               ; (start in foreground if true;default false)
minfds=1024                  ; (min. avail startup file descriptors;default 1024)
minprocs=200                 ; (min. avail process descriptors;default 200)
[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface
[supervisorctl]
serverurl=unix:///var/run/supervisor.sock ; use a unix:// URL  for a unix socket
[include]
files = /etc/supervisor.conf/*.conf
EOF

# app_Template
mkdir -p /etc/supervisor.conf/
cat >/etc/supervisor.conf/app.conf.bak<<-EOF
[program:app] ; 程序名称，在 supervisorctl 中通过这个值来对程序进行一系列的操作
autorestart=True      ; 程序异常退出后自动重启
autostart=True        ; 在 supervisord 启动的时候也自动启动
redirect_stderr=True  ; 把 stderr 重定向到 stdout，默认 false
environment=PATH="/home/app_env/bin"  ; 可以通过 environment 来添加需要的环境变量，一种常见的用法是使用指定的 virtualenv 环境
command=python server.py  ; 启动命令，与手动在命令行启动的命令是一样的
command=java -jar -Xmx3072m hotel-wechat-service-demo.jar
user=ubuntu           ; 用哪个用户启动
directory=/home/app/  ; 程序的启动目录
stdout_logfile_maxbytes = 20MB  ; stdout 日志文件大小，默认 50MB
stdout_logfile_backups = 20     ; stdout 日志文件备份数
; stdout 日志文件，需要注意当指定目录不存在时无法正常启动，所以需要手动创建目录（supervisord 会自动创建日志文件）
stdout_logfile = /data/logs/usercenter_stdout.log
EOF

    systemctl enable supervisord.service && systemctl start supervisord.service
    which supervisorctl &> /dev/null && echoGreen "supervisor已完成安装，可尽情享用！" || echoYellow "可能安装有问题，请检查！"
}

rsync_env() {
    yum -y install rsync
    cat >/etc/rsyncd.conf<<-EOF
# rsync_config_Template

port=873
#uid = www    
#gid = www 
# 与安全相关的参数
use chroot = no    
# 最大连接数
max connections = 200  
# 超时时间(单位/秒)
timeout = 300
# 进程对应的进程号文件    
#pid file = /var/run/rsyncd.pid
# 锁文件    
lock file = /var/run/rsync.lock 
# 日志文件 
log file = /var/log/rsyncd.log   

#模块名
[backup]
# 服务器提供访问的目录            
Path = /backup 
#忽略错误
ignore errors 
#可写    
read only = false
#不让列表（不能使用ls）  
list = false     
# 设置允许访问
hosts allow = 192.168.0.0/24
hosts deny = 0.0.0.0/32
#虚拟用户的账号密码文件
auth users = rsyncuser 
#文件认证的密码文件  
secrets file = /etc/rsync_server.pas   
EOF

    echo "rsyncuser:ziz123321" >/etc/rsync_server.pas && chmod 600 /etc/rsync_server.pas
    echo "ziz123321" >/etc/rsync_client.pas && chmod 600 /etc/rsync_client.pas
    systemctl enable rsyncd && systemctl start rsyncd 
    rsync --version &> /dev/null && echoGreen "rsync已完成安装，可尽情享用！" || echoYellow "可能安装有问题，请检查！"

}

redis_env(){
    [ -d /data/appdir/redis ] && echoRed "检测到/data/appdir已经安装redis" && exit 1

    cd /tmp && wget ${download_url}/redis/redis-4.0.6.tar.gz
    tar -xf redis-4.0.6.tar.gz -C /data/appdir  && cd /data/appdir/redis-4.0.6/ 
    make MALLOC=lib

    if [ $? -eq 0 ];then 
        cd src 
        make install 
    fi 

    mkdir -p  /etc/redis/  && cp /data/appdir/redis-4.0.6/redis.conf /etc/redis/26379.conf && mkdir /data/appdir/redis-4.0.6/data
        sed -i   "s#^bind 127.0.0.1#bind 0.0.0.0 #g" /etc/redis/26379.conf
        sed -i   's#protected-mode yes#protected-mode no#g' /etc/redis/26379.conf 
        sed -i   's#port 6379#port 26379#g' /etc/redis/26379.conf 
        sed -i   's#pidfile /var/run/redis_6379.pid#pidfile /var/run/redis_26379.pid#g'  /etc/redis/26379.conf
        sed -i   's#daemonize no#daemonize yes#g'  /etc/redis/26379.conf
        sed -i   's#dir ./#dir /data/appdir/redis-4.0.6/data#g'  /etc/redis/26379.conf
        #sed -i '$a  requirepass ziz123321_2019' /etc/redis/26379.conf

    \cp /data/appdir/redis-4.0.6/utils/redis_init_script /etc/init.d/redis
    if [ $? -eq 0 ];then
        sed -i 's#REDISPORT=6379#REDISPORT=26379#g' /etc/init.d/redis
        sed -i 's#EXEC=/usr/local/bin/redis-server#EXEC=/data/appdir/redis-4.0.6/src/redis-server#g' /etc/init.d/redis
        sed -i 's#CLIEXEC=/usr/local/bin/redis-cli#CLIEXEC=/data/appdir/redis-4.0.6/src/redis-cli#g' /etc/init.d/redis
    fi


    # REDIS
    echo "PATH=\$PATH:/data/appdir/redis-4.0.6/src/" >> /etc/profile && source /etc/profile


    /data/appdir/redis/src/redis-cli -v &> /dev/bull && echoGreen "redis 已经安装完成...."   || echoYellow "可能安装有问题，请检查...."
    rm -rf /tmp/redis*
}

rabbitmq_env(){
    which rabbitmqctl &>/dev/null &&  echoRed "检测到系统rabbitmqctl中有命令，故而退出！"  && exit 1
    cd /tmp/ && wget  ${download_url}/rabbitmq/{erlang-20.3.8.21-1.el7.x86_64.rpm,rabbitmq-server-3.7.7-1.el7.noarch.rpm}
    yum -y install erlang-20.3.8.21-1.el7.x86_64.rpm && yum -y install rabbitmq-server-3.7.7-1.el7.noarch.rpm
    systemctl enable rabbitmq-server.service && systemctl start rabbitmq-server.service
    # 开启web控制台
    rabbitmq-plugins enable rabbitmq_management
    which rabbitmqctl &> /dev/null && echoGreen "rabbitmq已完成安装，可尽情享用！" || echoYellow "可能安装有问题，请检查！"
    rm -rf /tmp/{erlang-20.3.8.21-1.el7.x86_64.rpm,rabbitmq-server-3.7.7-1.el7.noarch.rpm}
}

mongodb_env(){
    [ -L /data/appdir/mongodb ]  && echoRed "检测到/data/appdir已经安装mongodb" && exit 1
    cd /tmp/ && wget ${download_url}/mongodb/mongodb-linux-x86_64-rhel70-4.0.3.tgz  && tar -xf mongodb-linux-x86_64-rhel70-4.0.3.tgz -C /data/appdir/
    mv /data/appdir/mongodb-linux-x86_64-rhel70-4.0.3 /data/appdir/mongodb
    mkdir -p /data/appdir/mongodb/mongodb_data && mkdir -p /data/logs/mondodb_log && mkdir -p /etc/mongodb

# mongodb config 
cat >/etc/mongodb/mongodb.conf<<-EOF
port=27018
dbpath=/data/appdir/mongodb/mongodb_data
logpath=/data/logs/mondodb_log/mongo.log
logappend=true
auth=true  
bind_ip = 0.0.0.0
EOF

# mongodb service script
cat >/usr/lib/systemd/system/mongodb.service<<-EOF
[Unit]
Description=mongodb.service
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
ExecStart=/data/appdir/mongodb/bin/mongod  --config /etc/mongodb/mongodb.conf --logappend --fork
ExecReload=/bin/kill -s HUP \$MAINPID
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    # mongodb_env
    echo "PATH=$PATH:/data/appdir/mongodb/bin/" >>  /etc/profile && source /etc/profile

    systemctl enable mongodb.service &&  systemctl start mongodb.service
    /data/appdir/mongodb/bin/mongod -version &> /dev/null && echoGreen "mongodb已完成安装，可尽情享用！" || echoYellow "可能安装有问题，请检查！"
    rm -rf /tmp/mongodb*
}

py3(){
    /usr/bin/python3 -V &> /dev/null && echoRed "检测到系统中有python3.6命令，故而退出！" && rm -rf $dir && exit 1
    yum -y install zlib-devel bzip2-devel openssl-devel ncurses-devel sqlite-devel readline-devel tk-devel gdbm-devel db4-devel libpcap-devel xz-devel wget gcc gcc-c++
    cd /tmp/ && wget ${download_url}/python/Python-3.6.1.tar.xz && tar -xf Python-3.6.1.tar.xz && cd Python-3.6.1 
    ./configure --prefix=/data/appdir/python3.6 --enable-shared CFLAGS=-fPIC --enable-optimizations 
    make && make install
    cp /data/appdir/python3.6/lib/libpython3.6m.so.1.0 /usr/lib64/ && mkdir -p /root/.pip/ 

cat >> /root/.pip/pip.conf<<-EOF
    [global]
    index-url = https://mirrors.aliyun.com/pypi/simple/

    [install]
    trusted-host=mirrors.aliyun.com
EOF



    echo "PATH=$PATH:/data/appdir/python3.6/bin/" >> /etc/profile && source /etc/profile 
    /data/appdir/python3.6/bin/python3 -V && echoGreen "python已完成安装，可尽情享用！" || echoYellow "可能安装有问题，请检查！" 
    rm -rf /tmp/Python*
}

change_hostname(){
    CHANGENAME=$(whiptail --title "更改主机名" --inputbox "请输入新的主机名，用-来连接" 10 60 `hostname` 3>&1 1>&2 2>&3)
    exitstatus=$?
    if [ $exitstatus = 0 ]; then
        whiptail --title "Message" --msgbox "主机名由\n$(hostname)\n改为:\n$CHANGENAME\n" 10 60
        # whiptail --title "Yes/No Box" --yesno "Choose between Yes and No." --msgbox "主机名将由\n$(hostname)\n改为:\n\"$NAME\"\n""asdasdasd"  10 60
        hostnamectl set-hostname $CHANGENAME
        echo "hostname :  $(hostname)"
    else
        #echo "You chose Cancel."
        run_go
    fi
}


newvitrulhost(){
    #VM虚拟机克隆安装配置项。
    echo "----------------------------------------------------"
    # [ -e /etc/sysconfig/network-scripts/ifcfg-eth0 ] &&  echo -e "\n请勿\n    重复执行\n" &&  rm -rf $dir  &&exit 1
    hostnameip=$(hostname -I)
    int=$(ls /etc/sysconfig/network-scripts/ifcfg-*   | grep -v lo)
    eth=$(nmcli dev status | grep connected | awk '{print $1}')
    echo "当前IP地址： "[$hostnameip]
    echo "网卡名称：   "$eth
    echo "网络文件路径： "$int
    echo "当前主机名："$hostname
    echo "----------------------------------------------------"
    echo "即将进行："
    echo "         删除克隆的网卡信息、配置静态IP"
    echo "----------------------------------------------------"

    echo "    (1) 删除克隆机器的相关信息"
    rm  -f   /etc/udev/rules.d/*.rules
    #配置静态IP
    echo "----------------------------------------------------"
    echo "    (2) 配置静态IP,更改网卡名称"
    [ $eth != "eth0" ] && mv $int /etc/sysconfig/network-scripts/ifcfg-eth0 
    cat > /etc/sysconfig/network-scripts/ifcfg-eth0 <<EOF
TYPE=Ethernet                              
NAME=eth0                                   
DEVICE=eth0                                 
PROXY_METHOD=none                           
BROWSER_ONLY=no                             
BOOTPROTO=static                            
DEFROUTE=yes                                
IPV4_FAILURE_FATAL=no                       
IPV6INIT=yes                                
IPV6_AUTOCONF=yes                           
IPV6_DEFROUTE=yes                           
IPV6_FAILURE_FATAL=no                       
IPV6_ADDR_GEN_MODE=stable-privacy           
ONBOOT=yes                                  
IPADDR=$hostnameip                          
PREFIX=16                                   
GATEWAY=192.168.1.1                         
DNS1=233.5.5.5                              
DNS2=114.114.114.114
EOF

    sed  -i   's/GRUB_CMDLINE_LINUX=\"crashkernel/GRUB_CMDLINE_LINUX=\"net.ifnames=0 biosdevname=0\ crashkernel/g' /etc/default/grub
    grub2-mkconfig -o /etc/grub2.cfg   &> /dev/null
    echo "----------------------------------------------------"
    echo "    (3) 配置完成，五秒后重启"
    #read -n 1 -t 30  -p "是否重启主机reboot，y/n? " Number
    echo "----------------------------------------------------"
    echo "$(date)"
    echo "----------------------------------------------------"
    echo "rebooting....."
    #case $Number in
    #[Yy])
    #重启
    #   echo "" >  ./.bash_history   && history -c
    shutdown -r  now  && exit 0
    #;;
    #esac
    #   ;;
    #   esac
}

change_ip(){
    changeip=$(whiptail --title "更改IP" --inputbox "请输入新的IP地址" 10 60 `hostname -I` 3>&1 1>&2 2>&3)
    exitstatus=$?
    if [ $exitstatus = 0 ]; then
        whiptail --title "Message" --msgbox "IP地址将由\n$(hostname -I)\n改为:\n$changeip\n" 10 60
        #判断IP是否
        if echo $changeip | grep "^\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}$";then
            #判断文件是否规范
            [ ! -e /etc/sysconfig/network-scripts/ifcfg-eth0 ]   && echo -e "\n网卡配置文件不规范，请检查 ：\n  /etc/sysconfig/network-scripts/ifcfg-eth0\n"  &&  rm -rf $dir  &&  exit 1
            #判断IP是否可用
            ping -c 2 $changeip  > /dev/null && echo -e "\n[$changeip]\n 该IP已在使用中，请检查\n"   && rm -rf $dir && exit 1 || echo "该IP可用"
            #执行
                cat > /etc/sysconfig/network-scripts/ifcfg-eth0 <<EOF
TYPE=Ethernet                              
NAME=eth0                                   
DEVICE=eth0                                 
PROXY_METHOD=none                           
BROWSER_ONLY=no                             
BOOTPROTO=static                            
DEFROUTE=yes                                
IPV4_FAILURE_FATAL=no                       
IPV6INIT=yes                                
IPV6_AUTOCONF=yes                           
IPV6_DEFROUTE=yes                           
IPV6_FAILURE_FATAL=no                       
IPV6_ADDR_GEN_MODE=stable-privacy           
ONBOOT=yes                                  
IPADDR=$changeip                         
PREFIX=16                                   
GATEWAY=192.168.1.1                         
DNS1=233.5.5.5                              
DNS2=114.114.114.114
EOF
            #systemctl restart network
        else
            echo "输入的IP不合法"
        fi
    else
        run_go
    fi
}


linux_init() {
	yum_repo
    redhat_pkg
    security_env
    add_user
    kernel_env
    system_env
    crontab_env
}


A(){
    echo -e  "\e[36m ****\n您\n选\n择\n安\n装\n的\n是\n$OPTION\n，\n现\n在\n开\n始\n安\n装\n$OPTION\n****  \e[39m"
}


install_soft(){
    OPTION=$(whiptail --title "运维外挂-安装脚本" --menu "请选择想要安装的项目，上下键进行选择，回车即安装，左右键可选择<Cancel>返回上层！" 25 55 15 \
        "1" "openresty-1.15.8" \
        "2" "jdk-8-231" \
        "3" "tomcat-8.5" \
        "4" "maven-3.3" \
        "5" "node-12.16" \
        "6" "php-7.1" \
        "7" "zabbix-agent-4.2" \
        "8" "py-3.6" \
        "9" "redis-4.0.6" \
        "10" "mongodb-4.0.3" \
        "11" "rabbitmq-3.7.7" \
        "12" "rsyncd" \
        "13" "mysql5.7" \
        "14" "supervisor-3.4" 3>&1 1>&2 2>&3 )
    case $OPTION in 
    1) 
        A && openresty_env
        ;;
    2)
        A && jdk_env
        ;;
    3)
        A && tomcat_env
        ;;
    4) 
        A && maven_env
        ;;
    5) 
        A && node_env
        ;;
    6) 
        A && php_env
        ;;   
    7) 
        A && zibbix_agentd_env
        ;; 
    8) 
        A && py3
        ;;
    9) 
        A && redis_env
        ;;
    10) 
        A && mongodb_env
        ;;
    11) 
        A && rabbitmq_env
        ;;
    12) 
        A && rsync_env
        ;;
    13) 
        A && mysql_env
        ;;
    14) 
        A && supervisor_env
        ;;
    *)
        run_go
        ;;
    esac
}


initialization(){
    OPTION=$(whiptail --title "运维外挂-初始化菜单" --menu "请选择想要初始化的选项，上下键进行选择，回车即运行，左右键可选择<Cancel>返回上层！" 25 50 10 \
    "1" "VM Template clone_host init " \
    "2" "change hostname"  \
    "3" "change ip address" \
    "4" "init vm new CeontOS" \
    "5" "init aliyun new CeontOS " 3>&1 1>&2 2>&3 )
    case $OPTION in
    1)
        A && sleep 3 && newvitrulhost
        ;;
    2)
        A && sleep 3 && change_hostname
        ;;
    3)
        A && sleep 3 && change_ip
        ;;
    4)
        A && change_hostname && change_ip && linux_init
        ;;
    5)
        A && change_hostname  && linux_init
        ;;
    *)
        run_go
        ;;
    esac
}




Combination_install(){
    OPTION=$(whiptail --title "运维外挂-其他菜单" --menu "请选择相应的选项，上下键进行选择，回车即运行，左右键可选择<Cancel>返回上层！" 25 50 4 \
    "1" "安装lnmp" \
    "2" "安装ziztour前端软件" \
    "3" "安装ziztour后端软件" \
    "4" "其他"  3>&1 1>&2 2>&3 )

    case $OPTION in
    1)
        A  && openresty_env && php_env && mysql_env
        ;;
    2)
        A  && openresty_env && node_env && rsync_env
        ;;
    3)
        A && jdk_env &&  supervisor_env && rsync_env 
        ;;
    4)
        echoGreen "其他安装属性,未定义...."
        ;;
    *) 
         run_go
        ;;
    esac
}

#---------------------------------------------------------------------------------------------------------------------------------------------
#               入口菜单
#---------------------------------------------------------------------------------------------------------------------------------------------
run_go(){
    OPTION=$(whiptail --title "运维外挂-一步到位" --menu "请选择想要操作的菜单，回车即可进入！" 30 60 6 \
    "1" "安装软件(install soft)" \
    "2" "系统初始化(new initialization)" \
    "3" "组合软件包(Combination_install)"  \
    "4" "其他(others)"  3>&1 1>&2 2>&3 )

    case $OPTION in
    1)
        install_soft 
        ;;
    2)
        initialization
        ;;
    3)
        Combination_install
        ;;
    *) 
        echo "You chose Cancel."
        ;;
    esac
}

#调用首页
run_go