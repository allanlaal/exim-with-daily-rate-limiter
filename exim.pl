#!/usr/bin/perl

#smtpauth
#called by exim to verify if an smtp user is allowed to
#send email through the server
#possible success:
# user is in /etc/virtual/domain.com/passwd and password matches
# user is in /etc/passwd and password matches in /etc/shadow

sub smtpauth
{
	$username	= Exim::expand_string('$1');
	$password	= Exim::expand_string('$2');
	$extra		= Exim::expand_string('$3');
	$domain		= "";
	$unixuser	= 1;

	#check for netscape that offsets the login/pass by one
	if ($username eq "" && length($extra) > 0)
	{
		$username = $password;
		$password = $extra;
	}

	if ($username =~ /\@/)
	{
		$unixuser = 0;
		($username,$domain) = split(/\@/, $username);
		if ($domain eq "") { return "no"; }
	}

	if ($unixuser == 1)
	{
		#the username passed doesn't have a domain, so its a system account
		$homepath = (getpwnam($username))[7];
		if ($homepath eq "") { return 0; }
		open(PASSFILE, "< $homepath/.shadow") || return "no";
		$crypted_pass = <PASSFILE>;
		close PASSFILE;

		if ($crypted_pass eq crypt($password, $crypted_pass)) { return "yes"; }
		else { return "no"; }
	}
	else
	{
		#the username contain a domain, which is now in $domain.
		#this is a pure virtual pop account.

		open(PASSFILE, "< /etc/virtual/$domain/passwd") || return "no";
		while (<PASSFILE>)
		{
			($test_user,$test_pass) = split(/:/,$_);
			$test_pass =~ s/\n//g; #snip out the newline at the end
			if ($test_user eq $username)
			{
				if ($test_pass eq crypt($password, $test_pass))
				{
					close PASSFILE;
					return "yes";
				}
			}
		}
		close PASSFILE;
		return "no";
	}

	return "no";
}

sub find_uid_apache
{
	my ($work_path) = @_;
	my @pw;
	
	# $pwd will probably look like '/home/username/domains/domain.com/public_html'
	# it may or may not use /home though. others are /usr/home, but it's ultimately
	# specified in the /etc/passwd file.  We *could* parse through it, but for efficiency
	# reasons, we'll only check /home and /usr/home ..   if they change it, they can
	# manually adjust if needed.

	@dirs = split(/\//, $work_path);
	foreach $dir (@dirs)
	{
		# check the dir name for a valid user
		# get the home dir for that user
		# compare it with the first part of the work_path

		if ( (@pw = getpwnam($dir))  )
		{
			if ($work_path =~/^$pw[7]/)
			{
				return $pw[2];
			}
		}
	}
	return -1;
}

sub get_domain_owner
{
	my ($domain) = @_;
	my $username="";
	open(DOMAINOWNERS,"/etc/virtual/domainowners");
	while (<DOMAINOWNERS>)
	{
		$_ =~ s/\n//;
		my ($dmn,$usr) = split(/: /, $_);
		if ($dmn eq $domain)
		{
			close(DOMAINOWNERS);
			return $usr;
		}
	}
	close(DOMAINOWNERS);

	return -1;
}

sub find_uid_auth_id
{
	# this will be passwed either
	# 'username' or 'user@domain.com'

	my ($auth_id) = @_;
	my $unixuser = 1;
	my $domain = "";
	my $user = "";
	my $username = $auth_id;
	my @pw;

	if ($auth_id =~ /\@/)
	{
		$unixuser = 0;
		($user,$domain) = split(/\@/, $auth_id);
		if ($domain eq "") { return "-1"; }
        }

	if (!$unixuser)
	{
		# we need to take $domain and get the user from /etc/virtual/domainowners
		# once we find it, set $username
		my $u = get_domain_owner($domain);;
		if ($u != -1)
		{
			$username = $u;
		}
	}

	#log_str("username found from $auth_id: $username:\n");

	if ( (@pw = getpwnam($username))  )
	{
		return $pw[2];
	}

	return -1;
}

sub find_uid_sender
{
	my $sender_address = Exim::expand_string('$sender_address');

	my ($user,$domain) = split(/\@/, $sender_address);

	my $username = get_domain_owner($domain);

	if ( (@pw = getpwnam($username))  )
	{
		return $pw[2];
	}

	return -1;
}

sub find_uid
{
        my $uid = Exim::expand_string('$originator_uid');
	my $username = getpwuid($uid);
        my $auth_id = Exim::expand_string('$authenticated_id');
        my $work_path = $ENV{'PWD'};

	if ($username eq "apache" || $username eq "nobody")
	{
		$uid = find_uid_apache($work_path);
		if ($uid != -1) { return $uid; }
	}
	
	$uid = find_uid_auth_id($auth_id);
	if ($uid != -1) { return $uid; }

	# we don't want to rely on this, but it's all thats left.
	return find_uid_sender;
}

sub uid_exempt
{
        my ($uid) = @_;
        if ($uid == 0) { return 1; }

        my $name = getpwuid($uid);
        if ($name eq "root") { return 1; }
        if ($name eq "diradmin") { return 1; }

        return 0;
}


#check_limits
#used to enforce limits for the number of emails sent
#by a user.  It also logs the bandwidth of the data
#for received mail.

sub is_majordomo
{
        # checks if sender is a majordomo mailing list        
        my $alcom_sender = Exim::expand_string('$sender_address');
        my @alcom_split = split(/-/, $alcom_sender);
        if (@alcom_split[0] eq "owner") {
                my @alcom_domain = split(/@/, @alcom_split[1]);
                my $alcom_last = @alcom_domain - 1;
                my $alcom_path = "/etc/virtual/@alcom_domain[$alcom_last]/majordomo/lists/@alcom_domain[0]";
                if (-e $alcom_path) { return 1; }
        }
        
        return 0;
}


sub check_limits
{
        my $count = 0;
        my $alcom_limitfile;
        my $alcom_usagefile;

        #find the curent user
        $uid = find_uid();

        #log_str("Found uid: $uid\n");

        if (uid_exempt($uid)) { return "yes"; }

		
        if (is_majordomo()) {
        	$alcom_limitfile = "/etc/virtual/majordomolimit";
            $alcom_usagefile = "/etc/virtual/majordomousage";
        }
        else {
			$alcom_limitfile = "/etc/virtual/limit";
			$alcom_usagefile = "/etc/virtual/currentusage";
		}
        open (LIMIT, $alcom_limitfile);
        my $email_limit = int(<LIMIT>);
        close(LIMIT);
        

		my $name="";
		if ($email_limit > 0)
		{
				#check this users limit
				if (($name = getpwuid($uid)))
				{
						$count = (stat("$alcom_usagefile/$name"))[7];
						if ($count > $email_limit)
						{
								die("User $name has reached his email limit of $email_limit emails/min\n");
						}
						open(DAILYUSAGE, ">>/etc/virtual/usage/$name");
						print DAILYUSAGE "1";
						close(DAILYUSAGE);
						chmod (0660, "/etc/virtual/usage/$name");
						
						open(USAGE, ">>$alcom_usagefile/$name");
						print USAGE "1";
						close(USAGE);
						chmod (0660, "$alcom_usagefile/$name");
				}
		}

		my $sender_address = Exim::expand_string('$sender_address');
		my $mid = Exim::expand_string('$message_id');

		log_bandwidth($uid,"type=email&email=$sender_address&method=outgoing&id=$mid");

		return "yes"
        

}

sub log_email
{
	my($lp,$dmn) = @_;

	#log_str("logging $lp\@$dmn\n");
	my $user = get_domain_owner($dmn);
	if ($user == -1) { return "no"; }

	my $mid = Exim::expand_string('$message_id');

	if ( (@pw = getpwnam($user))  )
	{
		log_bandwidth($pw[2],"type=email&email=$lp\@$dmn&method=incoming&id=$mid");
	}

	return "yes";
}

sub save_virtual_user
{
	my $dmn = Exim::expand_string('$domain');
	my $lp  = Exim::expand_string('$local_part');
	my $usr = "";
	my $pss = "";
	my $entry = "";

	open (PASSWD, "/etc/virtual/$dmn/passwd") || return "no";

	while ($entry = <PASSWD>) {
		($usr,$pss) = split(/:/,$entry);
		if ($usr eq $lp) {
			close(PASSWD);
			log_email($lp, $dmn);
			return "yes";
		}
	}
	close (PASSWD);

	return "no";
}

sub log_bandwidth
{
	my ($uid,$data) = @_;
	my $name = getpwuid($uid);

	if (uid_exempt($uid)) { return; }

	if ($name eq "") { return; }

	my $bytes = Exim::expand_string('$message_size');

	if ($bytes == -1) { return; }

	open (BYTES, ">>/etc/virtual/usage/$name.bytes");
	print BYTES "$bytes=$data\n";
	close(BYTES);
	chmod (0660, "/etc/virtual/usage/$name.bytes");
}

sub log_str
{
	my ($str) = @_;

	open (LOG, ">> /tmp/test.txt");

	print LOG $str;

	close(LOG);
}
