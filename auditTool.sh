#!/bin/sh

# This is a test for the best practices for CentOS system configuration based on the CIS Benchmarks. This is not a wholescale test of the system and manual configuration is still necessary

# Color config for the prompts
bldred='\033[1;31m'
bldgrn='\033[1;32m'
bldblu='\033[1;34m'
bldylw='\033[1;33m' 
txtrst='\033[0m'

# pass prompt
pass () {
  printf "%b\n" "${bldgrn}[CONFIGURED]${txtrst} $1"
}

# warn prompt
warn () {
  printf "%b\n" "${bldred}[WARN]${txtrst} $1"
}

# 5.1.1 | Ensure cron daemon is enabled 
chkconfig crond on 
pass "5.1.1 -- cron daemon is enabled"

#5.1.2 | Ensure permissions on /etc/crontab are configured
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
pass "5.1.2 -- Permissions on /etc/crontab are configured"

#5.1.3 | Ensure permissions on /etc/cron.hourly are configured
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
pass "5.1.3 -- Permissions on /etc/cron.hourly are configured"

#5.1.4 | Ensure permissions on /etc/cron.daily are configured
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
pass "5.1.4 -- Permissions on /etc/cron.daily are configured"

#5.1.5 | Ensure permissions on /etc/cron.weekly are configured
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
pass "5.1.5 -- Permissions on /etc/cron.weekly are configured"

#5.1.6 | Ensure permissions on /etc/cron.monthly are configured
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
pass "5.1.6 -- Permissions on /etc/cron.monthly are configured"

#5.1.7 | Ensure permissions on /etc/cron.d are configured
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
pass "5.1.7 -- Permissions on /etc/cron.d are configured"

#5.1.8 | Ensure at/cron is restricted to authorized users
rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow
pass "5.1.8 -- at/cron is restricted to authorized users"

#5.2.1 | Ensure permissions on /etc/ssh/sshd_config are configured
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config
pass "5.2.1 -- Permissions on /etc/ssh/sshd_config are configured"

#5.2.2 | Ensure SSH Protocal is set to 2
warn "5.2.2 -- Must manually edit /etc/ssh/sshd_config file to set parameter as Protocol 2" 

#5.2.3 | Ensure SSH LogLevel is set to INFO
warn "5.2.3 -- Must manually edit /etc/ssh/sshd_config file to set parameter as LogLevel INFO"

#5.2.4 | Ensure SSH X11 forwarding is disabled
warn "5.2.4 -- Must manually edit /etc/ssh/sshd_config file to set parameter as X11Forwarding no"

#5.2.5 | Ensure SSH MaxAuthTries is set to 4 or less
warn "5.2.5 -- Must manually edit /etc/ssh/sshd_config file to set parameter as MaxAuthTries 4"

#5.2.6 | Ensure SSH IgnoreRhosts is enabled 
warn "5.2.6 -- Must manually edit /etc/ssh/sshd_config file to set parameter as IgnoreRhosts yes"

#5.2.7 | Ensure SSH HostbasedAuthentication is disabled 
warn "5.2.7 -- Must manually edit /etc/ssh/sshd_config file to set parameter as HostbasedAuthentication no"

#5.2.8 | Ensure SSH root login is disabled
warn "5.2.8 -- Must manually edit /etc/ssh/sshd_config file to set parameter as PermitRootLogin no"

#5.2.9 | Ensure SSH PermitEmptyPasswords is disabled
warn "5.2.9 -- Must manually edit /etc/ssh/sshd_config file to set parameter as PermitEmptyPasswords no"

#5.2.10 | Ensure SSH PermitUserEnvironment is disabled 
warn "5.2.10 -- Must manually edit /etc/ssh/sshd_config file to set parameter as PermitUserEnvironment no"

#5.2.11 | Ensure only approved ciphers are used
warn "5.2.11 -- Must manually edit /etc/ssh/sshd_config file to set parameter as Ciphers aes256-ctr,aes192-ctr,aes128-ctr"

#5.2.12 | Ensure only approved MAC algorithms are used
warn "5.2.12 -- Must manually edit /etc/ssh/sshd_config file to set parameter as MACS hmac-sha2-512,hmac-sha2-256"

#5.2.13 | Ensure SSH Idle Timeout Interval is configured
warn "5.2.13 -- Must manually edit /etc/ssh/sshd_config file to set parameter as ClientAliveInterval 300, ClientAliveCountMax 0"

#5.2.14 | Ensure SSH LoginGraceTime is set to one minute or less
warn "5.2.14 -- Must manually edit /etc/ssh/sshd_config file to set parameter as LoginGraceTime 60"

#5.2.15 | Ensure SSH access is limited
warn "5.2.15 -- Must manually edit /etc/ssh/sshd_config file to set parameter as AllowUsers <userlist>, AllowGroups <grouplist>, DenyUsers <userlist>, DenyGroups <grouplist>

#5.2.16 | Ensure SSH warning banner is configured
warn "5.2.16 -- Must manually edit /etc/ssh/sshd_config file to set parameter as Banner /etc/issue.net

#5.3.1 | Ensure password creation requirements are configured
warn "5.3.1 -- Must manually edit /etc/pam.d/password-auth and etc/pam.d/system-auth and configure: password requisite pam_cracklib.so try_first_pass retry=3 minlen=14 dcredit=-1 ucredit=-1 lcredit=-1"

#5.3.2 | Ensure lockout for failed password attempts is configured
warn "5.3.2 -- Must manually edit /etc/pam.d/password-auth and /etc/pam.d/system-auth and add: 
auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth [succes=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900"  

#5.3.3 | Ensure password reuse is limited
warn "5.3.3 -- Must manually edit /etc/pam.d/password-auth and /etc/pam.d/system-auth to include:
password sufficient pam_unix.so remember=5"

#5.3.4 | Ensure password hashing algorithm is SHA-512
cat /etc/paswd | awk -F: '( $3 >= 500 && $1 != "nfsnobody" ) {print $1 }'| xargs -n 1 chage -d 0
warn "5.3.4 -- Must manually edit /etc/pam.d/password-auth and /etc/pam.d/system-auth to include:
password sufficient pam_unix.so sha512"

#5.4.1.1 | Ensure password expiration is 90 days or less
warn "5.4.1.1 -- Must set PASS_MAX_DAYS parameter to 90 in /etc/login.defs file"

#5.4.1.2 | Ensure minimum days between password changes is 7 or more
warn "5.4.1.2 -- Must set PASS_MIN_DAYS parameter to 7 in /etc/login.defs file"

#5.4.1.3 | Ensure password expiration warning days is 7 or more
warn "5.4.1.2 -- Must set PASS_WARN_AGE parameter to 7 in /etc/login.defs file"

#5.4.1.4 | Ensure inactive password lock is 30 days or less
useradd -D -f 30
pass "5.4.1.4 -- Inactive password lock is 30 days or less"

#5.4.2 | Ensure system accounts are non-login
for user in `awk -F: '($3 < 500) {print $1 }' /etc/passwd` ; do 
	if [ $user != "root" ]; then
		usermod -L $user
		if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; 
then
      			usermod -s /sbin/nologin $user
		fi 
	fi
done
pass "5.4.2 -- System accounts are non-login"

#5.4.3 | Ensure default group for the root account is GID 0
usermod -g 0 root
pass "5.4.3 -- Default group for the root account is GID 0"

#5.4.4 | Ensure default user umask is 027 or more restrictive 
warn "5.4.4 -- Must manually edit /etc/bashrc and /etc/profiles to add or edit umask parameter"

#5.5 | Ensure root login is restricted to system console 
#this is not scored

#5.6 | Ensure access to the su command is restricted
warn "5.6 -- Must manually add: auth required pam_wheel.so use_uid to the /etc/pam.d/su file"

