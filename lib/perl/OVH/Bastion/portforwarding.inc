# vim: set filetype=perl ts=4 sw=4 sts=4 et:
package OVH::Bastion;

use common::sense;

use Time::Piece;    # $t->strftime

# Get the configured port range for local port forwarding
sub _get_port_range {
    my $config   = OVH::Bastion::load_configuration()->{value};
    my $min_port = $config->{'portForwardingLocalPortMin'};
    my $max_port = $config->{'portForwardingLocalPortMax'};

    # Validate port range
    if ($min_port < 1024 || $min_port > 65535 || $max_port < 1024 || $max_port > 65535 || $min_port >= $max_port) {
        return R('ERR_INVALID_CONFIGURATION', msg => "Invalid port forwarding port range: $min_port-$max_port");
    }

    return R('OK', value => {min => $min_port, max => $max_port});
}

# Get all currently allocated local ports from all users and groups
sub _get_allocated_ports {
    my %allocated_ports;
    my %allocated_ids;

    # Check all user port forward files
    my $fnret = OVH::Bastion::get_account_list();
    if ($fnret && $fnret->value) {
        foreach my $account (keys %{$fnret->value}) {
            my $file = "/home/allowkeeper/$account/allowed.forward";
            if (-r $file) {
                my $result = _parse_port_file($file);
                if ($result && $result->value) {
                    my $ports = $result->value;
                    %allocated_ports = (%allocated_ports, %{$ports->{ports}});
                    %allocated_ids   = (%allocated_ids,   %{$ports->{ids}});
                }
            }
        }
    }

    # Check all group port forward files
    $fnret = OVH::Bastion::get_group_list();
    if ($fnret && $fnret->value) {
        foreach my $group (keys %{$fnret->value}) {
            my $file = "/home/key$group/allowed.forward";
            if (-r $file) {
                my $result = _parse_port_file($file);
                if ($result && $result->value) {
                    my $ports = $result->value;
                    %allocated_ports = (%allocated_ports, %{$ports->{ports}});
                    %allocated_ids   = (%allocated_ids,   %{$ports->{ids}});
                }
            }
        }
    }

    return R('OK', value => {ports => \%allocated_ports, ids => \%allocated_ids});
}

# Parse a port forwarding file to extract allocated ports and IDs
sub _parse_port_file {
    my ($file) = @_;
    my %ports;
    my %ids;

    my $fh;
    if (!open($fh, '<', $file)) {
        return R('ERR_CANNOT_OPEN_FILE', msg => "Cannot open $file: $!");
    }

    while (my $line = <$fh>) {
        chomp $line;
        next if $line =~ /^\s*#/ || $line =~ /^\s*$/;

        # Parse line format: remote_ip:ssh_port:forward_port:remote_user:local_port:rule_id
        my @fields = split /:/, $line;
        if (@fields >= 6) {
            my $local_port = $fields[4];
            my $rule_id    = $fields[5];

            # Extract just the ID part (before any comments)
            $rule_id =~ s/\s.*$//;

            if ($local_port =~ /^\d+$/ && $rule_id) {
                $ports{$local_port} = 1;
                $ids{$rule_id}      = 1;
            }
        }
    }
    close($fh);

    return R('OK', value => {ports => \%ports, ids => \%ids});
}

# Generate a unique rule ID for a port forwarding rule
sub _generate_rule_id {
    my ($allocated_ids) = @_;

    # Generate a random 8-character alphanumeric ID
    my @chars = ('a' .. 'z', 'A' .. 'Z', '0' .. '9');
    my $id;
    my $attempts = 0;

    do {
        $id = join '', map { $chars[rand @chars] } 1 .. 8;
        $attempts++;
        return R('ERR_PORT_ALLOCATION_FAILED', msg => "Could not generate unique port ID after $attempts attempts")
          if $attempts > 1000;
    } while (exists $allocated_ids->{$id});

    return R('OK', value => $id);
}

# Check if a port is in use by the system using either ss or netstat
sub _is_port_in_use {
    my ($port) = @_;

    # Try ss first (modern systems)
    my ($ss_test, $ss_exit_code) = OVH::Bastion::execute(cmd => ['ss', '-ln'], noisy_stderr => 0);
    if ($ss_exit_code == 0 && $ss_test && $ss_test =~ /:$port /) {
        return 1;    # Port is in use
    }
    if ($ss_exit_code == 0) {
        return 0;    # ss worked but port not found, so it's free
    }

    # Fallback to netstat (older systems)
    my ($netstat_test, $netstat_exit_code) = OVH::Bastion::execute(cmd => ['netstat', '-ln'], noisy_stderr => 0);
    if ($netstat_exit_code == 0 && $netstat_test && $netstat_test =~ /:$port /) {
        return 1;    # Port is in use
    }
    if ($netstat_exit_code == 0) {
        return 0;    # netstat worked but port not found, so it's free
    }

    # If both commands fail, assume port is free (conservative approach)
    warn_syslog("Warning: Both 'ss' and 'netstat' commands failed, assuming port $port is free");
    return 0;
}

# Check if a port forward rule already exists in a specific file
sub _check_existing_rule_in_file {
    my ($file, $remote_ip, $forward_port, $remote_user) = @_;

    if (!-r $file) {
        return R('KO_NOT_FOUND', msg => "File not readable");
    }

    if (open(my $fh, '<', $file)) {
        while (my $line = <$fh>) {
            chomp $line;
            next if $line =~ /^\s*#/;    # skip commented lines
            next if $line =~ /^\s*$/;    # skip empty lines

            # Parse: remote_ip:ssh_port:forward_port:remote_user:local_port:rule_id
            if ($line =~ m{^(\[[^\]]+\]|[^:]+):([^:]*):([^:]*):([^:]*):([^:]*):([^:\s]*)\s*}) {
                my (
                    $file_remote_ip,   $file_ssh_port,   $file_forward_port,
                    $file_remote_user, $file_local_port, $file_rule_id
                ) = ($1, $2, $3, $4, $5, $6);

                # Remove brackets from IPv6 addresses for comparison
                $file_remote_ip =~ s/^\[|\]$//g;
                my $check_remote_ip = $remote_ip;
                $check_remote_ip =~ s/^\[|\]$//g;

                # Handle wildcards
                $file_forward_port = undef if $file_forward_port eq '*';
                $file_remote_user  = undef if $file_remote_user eq '*';

                # Check for exact match on the uniqueness criteria
                if (   $file_remote_ip eq $check_remote_ip
                    && ($file_forward_port // '') eq ($forward_port // '')
                    && ($file_remote_user  // '') eq ($remote_user  // ''))
                {
                    close($fh);
                    return R(
                        'OK',
                        msg   => "Rule already exists",
                        value => {
                            file       => $file,
                            line       => $line,
                            local_port => $file_local_port,
                            rule_id    => $file_rule_id
                        }
                    );
                }
            }
        }
        close($fh);
    }

    return R('KO_NOT_FOUND', msg => "Rule does not exist");
}

# Allocate a new unique local port
sub _allocate_local_port {
    my $range_result = _get_port_range();
    return $range_result unless $range_result;

    my $min_port = $range_result->value->{min};
    my $max_port = $range_result->value->{max};

    my $allocated_result = _get_allocated_ports();
    return $allocated_result unless $allocated_result;

    my $allocated_ports = $allocated_result->value->{ports};
    my $allocated_ids   = $allocated_result->value->{ids};

    # Try to find a free port (with some randomization to avoid conflicts)
    my $attempts     = 0;
    my $max_attempts = ($max_port - $min_port + 1) * 2;    # Try twice the range size

    while ($attempts < $max_attempts) {
        my $port = $min_port + int(rand($max_port - $min_port + 1));

        if (!exists $allocated_ports->{$port}) {
            # Check if port is actually available (not in use by system)
            if (_is_port_in_use($port)) {
                # Port is in use by system, try another
                $attempts++;
                next;
            }

            # Generate unique ID
            my $id_result = _generate_rule_id($allocated_ids);
            return $id_result unless $id_result;

            return R('OK', value => {port => $port, id => $id_result->value});
        }
        $attempts++;
    }

    return R('ERR_PORT_ALLOCATION_FAILED',
        msg => "Could not find a free port in range $min_port-$max_port after $attempts attempts");
}

# all port forwarding ACL modifications (on groups, on accounts, including group-guests) are handled here
sub portforward_modify {
    my %params = @_;

    # Check if port forwarding is enabled in configuration
    my $fnret = OVH::Bastion::load_configuration();
    if (!$fnret) {
        return R('ERR_CONFIGURATION', msg => "Failed to load configuration");
    }
    my $config = $fnret->value;
    if (!$config->{'portForwardingEnabled'}) {
        return R('ERR_FORBIDDEN', msg => "Port forwarding feature is disabled on this bastion");
    }

    my $action = $params{'action'};    # add or del

    my $remote_user  = $params{'remote_user'};     # can be undef or '*' for a user-wildcard access
    my $remote_ip    = $params{'remote_ip'};       # can be a single ip or prefix
    my $ssh_port     = $params{'ssh_port'};        # SSH server port (default 22)
    my $forward_port = $params{'forward_port'};    # Port to forward through the tunnel

    my $ttl     = $params{'ttl'};
    my $comment = $params{'comment'};

    my $way     = $params{'way'};                  # group, groupguest, personal
    my $group   = $params{'group'};                # only for way=group or way=groupguest
    my $account = $params{'account'};              # only for way=personal

    my $forceKey      = $params{'forceKey'};
    my $forcePassword = $params{'forcePassword'};

    my $dryrun = $params{'dryrun'};                # don't do anything, just check params and prereqs
    my $sudo   = $params{'sudo'};                  # passed as-is to subs we use

    # deny accesses wider than these prefixes
    my %widestVxPrefix = (
        4 => $params{'widestV4Prefix'},
        6 => $params{'widestV6Prefix'},
    );

    if (!grep { $action eq $_ } qw{ add del clear }) {
        return R('ERR_INVALID_PARAMETER', msg => "Action should be add, del or clear");
    }

    if ($action ne 'clear') {
        foreach my $mandatoryParam (qw/action remote_ip way/) {
            if (!$params{$mandatoryParam}) {
                return R('ERR_MISSING_PARAMETER', msg => "Missing parameter '$mandatoryParam'");
            }
        }
    }

    # if undef, default to sudo==1
    $sudo //= 1;

    # normalize * into undef
    # also, due to how plugins work, sometimes remote_user and ports are just '', make them undef in those cases
    undef $remote_user  if (defined $remote_user  && ($remote_user eq '*'  || $remote_user eq ''));
    undef $ssh_port     if (defined $ssh_port     && ($ssh_port eq '*'     || $ssh_port eq ''));
    undef $forward_port if (defined $forward_port && ($forward_port eq '*' || $forward_port eq ''));

    # Default SSH port to 22 if not specified
    $ssh_port //= 22;

    # check way
    if ($way eq 'personal') {
        return R('ERR_INVALID_PARAMETER', msg => "Group parameter specified with way=personal") if defined $group;
        return R('ERR_MISSING_PARAMETER', msg => "Account parameter mandatory with way=personal")
          if not defined $account;
    }
    elsif ($way eq 'group') {
        return R('ERR_MISSING_PARAMETER', msg => "Group parameter mandatory with way=group")   if not defined $group;
        return R('ERR_INVALID_PARAMETER', msg => "Account parameter specified with way=group") if defined $account;
    }
    elsif ($way eq 'groupguest') {
        if (not defined $account or not defined $group) {
            return R('ERR_MISSING_PARAMETER', msg => "Account or group parameter missing with way=groupguest");
        }
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Parameter 'way' must be either personal, group or groupguest");
    }

    # check remote_ip
    if ($action ne 'clear') {
        $fnret = OVH::Bastion::is_valid_ip(ip => $remote_ip, allowSubnets => 1);
        return $fnret unless $fnret;
        $remote_ip = $fnret->value->{'ip'};

        if ($fnret->value->{'type'} eq 'subnet') {
            my $ipVersion = $fnret->value->{'version'};
            if (defined $widestVxPrefix{$ipVersion} && $fnret->value->{'prefixlen'} < $widestVxPrefix{$ipVersion}) {
                return R(
                    'ERR_INVALID_PARAMETER',
                    msg => sprintf(
                        "Specified prefix length (/%d) is too wide, maximum allowed for IPv%d is /%d by policy",
                        $fnret->value->{'prefixlen'},
                        $ipVersion, $widestVxPrefix{$ipVersion}
                    ),
                );
            }
        }
    }

    # check ssh_port
    if (defined $ssh_port) {
        $fnret = OVH::Bastion::is_valid_port(port => $ssh_port);
        return $fnret unless $fnret;
        $ssh_port = $fnret->value;
    }

    # check forward_port
    if (defined $forward_port) {
        $fnret = OVH::Bastion::is_valid_port(port => $forward_port);
        return $fnret unless $fnret;
        $forward_port = $fnret->value;
    }

    # check remote user
    if (defined $remote_user) {
        $fnret = OVH::Bastion::is_valid_remote_user(user => $remote_user, allowWildcards => 1);
        return $fnret unless $fnret;
        $remote_user = $fnret->value;
    }

    # check account
    my ($remoteaccount, $sysaccount);
    if (defined $account) {
        # accountType==normal : account must NOT be a realm_* account (but can be a realm/jdoe account)
        $fnret =
          OVH::Bastion::is_bastion_account_valid_and_existing(account => $account, accountType => 'normal', cache => 1);
        $fnret or return $fnret;
        $sysaccount    = $fnret->value->{'sysaccount'};
        $account       = $fnret->value->{'account'};
        $remoteaccount = $fnret->value->{'remoteaccount'};
    }

    # check group
    my $shortGroup;
    if (defined $group) {
        $fnret = OVH::Bastion::is_valid_group_and_existing(group => $group, groupType => 'key', cache => 1);
        $fnret or return $fnret;
        $group      = $fnret->value->{'group'};         # untainted
        $shortGroup = $fnret->value->{'shortGroup'};    # untainted
    }

    # check key fingerprint
    if ($forceKey) {
        $fnret = OVH::Bastion::is_valid_fingerprint(fingerprint => $forceKey);
        $fnret or return $fnret;
        $forceKey = $fnret->value->{'fingerprint'};
    }

    # check password hash
    if ($forcePassword) {
        $fnret = OVH::Bastion::is_valid_hash(hash => $forcePassword);
        $fnret or return $fnret;
        $forcePassword = $fnret->value->{'hash'};
    }

    if ($ttl) {
        if ($ttl =~ /^(\d+)$/) {
            $ttl = $1;
        }
        else {
            return R('ERR_INVALID_PARAMETER', msg => "The TTL must be numeric");
        }
    }

    # check if the caller has the right to make the change they're asking
    # ... 1. either $> is allowkeeper and $ENV{'SUDO_USER'} is the requesting account
    # ... 2. or $> is $grouptomodify  and $ENV{'SUDO_USER'} is the requesting account

    my ($running_as) = (getpwuid($>))[0] =~ /([0-9a-zA-Z_.-]+)/;
    my $requester;
    if ($sudo) {
        ($requester) = $ENV{'SUDO_USER'} =~ /([0-9a-zA-Z_.-]+)/;
    }
    else {
        $requester = $running_as;
    }

    # requester can never be a realm_* account, because it's shared and should not be able to add access to anything
    return R('ERR_SECURITY_VIOLATION', msg => "Requester can't be a realm user") if $requester =~ /^realm_/;

    my @one_should_succeed;
    my $expected_running_as = 'allowkeeper';

    if ($way eq 'personal') {
        if ($requester eq $account) {
            push @one_should_succeed,
              OVH::Bastion::is_user_in_group(
                user  => $requester,
                group => 'osh-self' . ucfirst($action) . 'PersonalAccess',
                sudo  => $sudo,
              );
        }

        # this is not a else here: somebody who has the account* right doesn't need the self* right
        push @one_should_succeed,
          OVH::Bastion::is_user_in_group(
            user  => $requester,
            group => 'osh-account' . ucfirst($action) . 'PersonalAccess',
            sudo  => $sudo
          );
    }
    elsif ($way eq 'group') {
        $expected_running_as = $group;
        push @one_should_succeed,
          OVH::Bastion::is_group_aclkeeper(account => $requester, group => $shortGroup, superowner => 1, sudo => $sudo);
    }
    elsif ($way eq 'groupguest') {
        push @one_should_succeed,
          OVH::Bastion::is_group_gatekeeper(
            account    => $requester,
            group      => $shortGroup,
            superowner => 1,
            sudo       => $sudo
          );
    }

    if ($running_as ne $expected_running_as && !$dryrun) {
        warn_syslog("Security violation: current running user ($running_as) unexpected (wanted $expected_running_as)");
        return R('ERR_SECURITY_VIOLATION', msg => "Current running user unexpected");
    }

    if (grep({ $_ } @one_should_succeed) == 0 && $requester ne 'root' && !$dryrun) {
        warn_syslog(
                "Security violation: requesting user '$requester' doesn't have the right to do that (way=$way, group="
              . ($shortGroup ? '<u>' : $shortGroup)
              . ")");
        return R('ERR_SECURITY_VIOLATION', msg => "You're not allowed to do that");
    }

    # end of dryrun
    return R('OK', msg => "Would have modified the access ($action) but we've been called with dryrun") if $dryrun;

    # For add operations, verify that the account has underlying SSH access to the destination
    if ($action eq 'add' && $way eq 'personal') {
        osh_debug("Checking if account $account has SSH access to $remote_ip:$ssh_port as user $remote_user");

        # Check if the account has SSH access to this destination
        $fnret = OVH::Bastion::is_access_granted(
            account => $account,
            ip      => $remote_ip,
            port    => $ssh_port,
            user    => $remote_user,
            ipfrom  => '127.0.0.1',    # Dummy IP since we're just checking access rules
        );

        if (!$fnret) {
            my $machine =
              OVH::Bastion::machine_display(ip => $remote_ip, port => $ssh_port, user => $remote_user)->value;
            return R('ERR_ACCESS_DENIED',
                msg => "Account $account doesn't have SSH access to $machine. "
                  . "Port forwarding access can only be granted to destinations where SSH access is already allowed.");
        }

        osh_debug("SSH access validation passed for $account to $remote_ip:$ssh_port");
    }

    # For group-based port forwards, check if there's group access to the destination
    if ($action eq 'add' && $way eq 'group') {
        osh_debug("Checking if group $shortGroup has SSH access to $remote_ip:$ssh_port as user $remote_user");

        # Check if the group has SSH access to this destination
        $fnret = OVH::Bastion::is_access_way_granted(
            ip    => $remote_ip,
            port  => $ssh_port,
            user  => $remote_user,
            way   => 'group',
            group => $shortGroup,
        );

        if (!$fnret) {
            my $machine =
              OVH::Bastion::machine_display(ip => $remote_ip, port => $ssh_port, user => $remote_user)->value;
            return R('ERR_ACCESS_DENIED',
                msg => "Group $shortGroup doesn't have SSH access to $machine. "
                  . "Port forwarding access can only be granted to destinations where SSH access is already allowed.");
        }

        osh_debug("SSH access validation passed for group $shortGroup to $remote_ip:$ssh_port");
    }

    # For groupguest port forwards, check if the account has access through the group
    if ($action eq 'add' && $way eq 'groupguest') {
        osh_debug(
            "Checking if account $account has SSH access through group $shortGroup to $remote_ip:$ssh_port as user $remote_user"
        );

        # Check if the account has access to this group and the group has access to the destination
        $fnret = OVH::Bastion::is_access_granted(
            account => $account,
            ip      => $remote_ip,
            port    => $ssh_port,
            user    => $remote_user,
            ipfrom  => '127.0.0.1',    # Dummy IP since we're just checking access rules
        );

        if (!$fnret) {
            my $machine =
              OVH::Bastion::machine_display(ip => $remote_ip, port => $ssh_port, user => $remote_user)->value;
            return R('ERR_ACCESS_DENIED',
                msg => "Account $account doesn't have SSH access to $machine through group $shortGroup. "
                  . "Port forwarding access can only be granted to destinations where SSH access is already allowed.");
        }

        # Verify the access is through the specific group we're adding guest access for
        my $foundGroupAccess = 0;
        foreach my $grant (@{$fnret->value || []}) {
            if ($grant->{'type'} =~ /^group/ && defined $grant->{'group'} && $grant->{'group'} eq $shortGroup) {
                $foundGroupAccess = 1;
                last;
            }
        }

        if (!$foundGroupAccess) {
            my $machine =
              OVH::Bastion::machine_display(ip => $remote_ip, port => $ssh_port, user => $remote_user)->value;
            return R('ERR_ACCESS_DENIED',
                msg => "Account $account doesn't have SSH access to $machine specifically through group $shortGroup. "
                  . "Guest port forwarding access can only be granted for destinations accessible through the specified group."
            );
        }

        osh_debug(
            "SSH access validation passed for account $account through group $shortGroup to $remote_ip:$ssh_port");
    }

    if ($action ne 'clear') {
        # now, check if the port forwarding access we're being asked to change is already in place or not
        osh_debug(
            "for action $action of $remote_user\@$remote_ip:$ssh_port->$forward_port of way $way with account=$account and group=$group, checking if already granted"
        );
        $fnret = OVH::Bastion::is_portforward_way_granted(
            remote_user  => $remote_user,
            remote_ip    => $remote_ip,
            ssh_port     => $ssh_port,
            forward_port => $forward_port,
            way          => $way,
            group        => $shortGroup,
            account      => $account,
            exactMatch   => 1,               # we're checking if the exact right we're asked to modify exists or not
        );
        osh_debug("... result is $fnret");

        if ($action eq 'add' and $fnret) {
            return R('OK_NO_CHANGE', msg => "The requested port forward access to add was already granted");
        }
        elsif ($action eq 'del' and not $fnret) {
            return R('OK_NO_CHANGE',
                msg => "The requested port forward access to delete was not found, no change made");
        }
    }

    # ok, now do the change, first define this sub

    my $_portforward_modify_file = sub {
        my %sub_params = @_;
        my $file       = $sub_params{'file'};

        # we don't check our params or the rights because our caller already did, guaranteed by the scoping of this sub

        # check if we can access the file
        if (!(-e $file)) {
            # it doesn't exist yet, create it
            OVH::Bastion::touch_file($file, oct(644));
            if (!(-e $file)) {
                warn_syslog("Couldn't create $file ($!)");
                return R('ERR_CANNOT_CREATE_FILE', msg => "File '$file' is missing and couldn't be created");
            }
        }

        # can we write to it ?
        if (!(-w $file)) {
            warn_syslog("Couldn't write to $file ($!)");
            return R('ERR_CANNOT_OPEN_FILE', msg => "File '$file' cannot be written to");
        }

        # if we're being asked to clear, it's pretty straightforward
        if ($action eq 'clear') {
            if (truncate($file, 0)) {
                OVH::Bastion::syslogFormatted(
                    severity => 'info',
                    type     => 'portforward',
                    fields   => [
                        ['action',  'clear'],
                        ['type',    $params{'way'}],
                        ['group',   $shortGroup],
                        ['account', $params{'account'}],
                    ]
                );
                return R('OK', msg => "Port forward accesses successfully cleared");
            }
            else {
                warn_syslog("Couldn't truncate $file ($!)");
                return R('ERR_CANNOT_OPEN_FILE', msg => "Unable to truncate $file");
            }
        }

        # build the line we're either adding or looking for (to delete it)
        my $entry = (index($remote_ip, ':') >= 0 ? "[$remote_ip]" : $remote_ip);
        $entry .= ':' . ($ssh_port     || '*');
        $entry .= ':' . ($forward_port || '*');
        $entry .= ':' . ($remote_user  || '*');

        my $local_port;
        my $rule_id;

        if ($action eq 'add') {
            # Check if this exact rule already exists in the target file (same remote_ip, forward_port, remote_user)
            my $existing_check = _check_existing_rule_in_file($file, $remote_ip, $forward_port, $remote_user);
            if ($existing_check && $existing_check->is_ok) {
                return R('ERR_ALREADY_EXISTING', msg => "This port forward rule already exists");
            }

            # Allocate a unique local port and ID for new entries
            my $allocation_result = _allocate_local_port();
            if (!$allocation_result) {
                warn_syslog("Port allocation failed: " . $allocation_result->msg);
                return $allocation_result;
            }

            $local_port = $allocation_result->value->{port};
            $rule_id    = $allocation_result->value->{id};

            $entry .= ':' . $local_port;
            $entry .= ':' . $rule_id;
        }

        my $t            = localtime(time);
        my $fmt          = "%Y-%m-%d %H:%M:%S";
        my $date         = $t->strftime($fmt);
        my $entryComment = "# $action by " . $ENV{'SUDO_USER'} . " on $date";

        # if we're adding it, append other parameters as comments
        if ($action eq 'add') {
            $entry .= " $entryComment";

            if ($forceKey) {
                # hash is case-sensitive only for new SHA256 format
                $forceKey = lc($forceKey) if ($forceKey !~ /^sha256:/i);
                $entry .= " # FORCEKEY=" . $forceKey;
            }
            if ($forcePassword) {
                $entry .= " # FORCEPASSWORD=" . $forcePassword;
            }
            if ($ttl) {
                $entry .= " # EXPIRY=" . (time() + $ttl);
            }
            if ($comment) {
                $comment =~ s{[#<>\\"']}{_}g;
                $entry .= " # COMMENT=<" . $comment . ">";
            }
        }

        # to be extra sure, remove any \n in $entry, which is impossible because we vetted all the params,
        # but if somehow we failed, we'll be sure it doesn't permit to add multiple rights at once
        $entry =~ s/[\r\n]*//gm;

        # now, do the change
        my $returnmsg;
        if ($action eq 'add') {
            osh_debug("going to add entry '$entry'");
            if (open(my $fh_file, '>>', $file)) {
                print $fh_file $entry . "\n";
                close($fh_file);
            }
            else {
                return R('ERR_CANNOT_OPEN_FILE', msg => "Error opening $file: $!");
            }
            my $machine =
              "$remote_ip:" . ($ssh_port || '*') . "->" . ($forward_port || '*') . " (" . ($remote_user || '*') . ")";
            my $ttlmsg =
              $ttl ? (' (expires in ' . OVH::Bastion::duration2human(seconds => $ttl)->value->{'human'} . ')') : '';

            $returnmsg = "Port forward access to $machine successfully added$ttlmsg";
            if ($local_port && $rule_id) {
                $returnmsg .= " [Local port: $local_port, ID: $rule_id]";
            }
        }
        elsif ($action eq 'del') {
            # For deletion, we can match either:
            # 1. By the first 4 fields (remote_ip:ssh_port:forward_port:remote_user) - traditional way
            # 2. By rule_id if provided in the params
            my $search_pattern    = quotemeta($entry);
            my $rule_id_to_delete = $params{'rule_id'};

            if (open(my $fh_file, '<', $file)) {
                my $newFile;
                my $found = 0;
                while (my $line = <$fh_file>) {
                    chomp $line;

                    # Skip comment lines
                    if ($line =~ /^\s*#/ || $line =~ /^\s*$/) {
                        $newFile .= $line . "\n";
                        next;
                    }

                    my $should_delete = 0;

                    # Parse the line to check for matches
                    my @fields = split /:/, $line, 7;    # Split into max 7 parts to handle comments

                    if (@fields >= 6) {
                        # Check for rule ID match if rule_id was provided
                        if ($rule_id_to_delete) {
                            my $line_rule_id = $fields[5];
                            $line_rule_id =~ s/\s.*$//;    # Remove any trailing comments
                            if ($line_rule_id eq $rule_id_to_delete) {
                                $should_delete = 1;
                            }
                        }
                        else {
                            # Traditional match on first 4 fields
                            my $line_entry = join ':', @fields[0 .. 3];
                            if ($line_entry eq $entry) {
                                $should_delete = 1;
                            }
                        }
                    }
                    elsif (@fields >= 4 && !$rule_id_to_delete) {
                        # Fallback for old format entries (without local_port:rule_id)
                        my $line_entry = join ':', @fields[0 .. 3];
                        if ($line_entry eq $entry) {
                            $should_delete = 1;
                        }
                    }

                    if ($should_delete) {
                        # Found matching entry, comment it out
                        my $comment_text =
                          $comment ? $comment : "removed by " . $ENV{'SUDO_USER'} . " on " . localtime(time);
                        $line = "# $line # $comment_text";
                        $found++;
                    }

                    $newFile .= $line . "\n";
                }
                close($fh_file);

                if ($found) {
                    # now rewrite
                    if (open(my $fh_file, '>', $file)) {
                        print $fh_file $newFile;
                        close($fh_file);
                        if ($rule_id_to_delete) {
                            $returnmsg = "Port forward rule with ID $rule_id_to_delete successfully removed";
                        }
                        else {
                            my $machine =
                                "$remote_ip:"
                              . ($ssh_port     || '*') . "->"
                              . ($forward_port || '*') . " ("
                              . ($remote_user  || '*') . ")";
                            $returnmsg = "Port forward access to $machine successfully removed";
                        }
                    }
                    else {
                        return R('ERR_CANNOT_OPEN_FILE', msg => "Unable to write open $file");
                    }
                }
                else {
                    if ($rule_id_to_delete) {
                        return R('OK_NO_CHANGE', msg => "Rule with ID $rule_id_to_delete was not found in $file");
                    }
                    else {
                        return R('OK_NO_CHANGE', msg => "Entry $entry was not present in file $file");
                    }
                }
            }
        }
        OVH::Bastion::syslogFormatted(
            severity => 'info',
            type     => 'portforward',
            fields   => [
                ['action',        $params{'action'}],
                ['type',          $params{'way'}],
                ['group',         $shortGroup],
                ['account',       $params{'account'}],
                ['remote_user',   $params{'remote_user'}],
                ['remote_ip',     $params{'remote_ip'}],
                ['ssh_port',      $params{'ssh_port'}],
                ['forward_port',  $params{'forward_port'}],
                ['local_port',    $local_port],
                ['rule_id',       $rule_id],
                ['ttl',           $params{'ttl'}],
                ['comment',       $params{'comment'}],
                ['forceKey',      $params{'forceKey'}],
                ['forcePassword', $params{'forcePassword'}],
            ]
        );
        return R('OK', msg => $returnmsg) if $returnmsg;
        return R('ERR_INTERNAL');
    };    # end of sub definition

    # then call the sub we just defined
    delete $params{'file'};
    my $ret;
    my $prefix = $remoteaccount ? "allowed_$remoteaccount" : "allowed";
    if ($way eq 'personal') {
        $ret = $_portforward_modify_file->(%params, file => "/home/allowkeeper/$sysaccount/$prefix.forward");
    }
    elsif ($way eq 'group') {
        $ret = $_portforward_modify_file->(%params, file => "/home/$group/allowed.forward");
    }
    elsif ($way eq 'groupguest') {
        $ret = $_portforward_modify_file->(
            %params, file => "/home/allowkeeper/$sysaccount/$prefix.partial.$shortGroup.forward"
        );
    }
    osh_debug("_portforward_modify_file() said $ret");
    return $ret if defined $ret;

    return R('ERR_INTERNAL');    # unreachable
}

# Check if a specific port forward access is granted via a specific way (personal, group, groupguest)
sub is_portforward_way_granted {
    my %params = @_;

    # Check if port forwarding is enabled in configuration
    my $fnret = OVH::Bastion::load_configuration();
    if (!$fnret) {
        return R('ERR_CONFIGURATION', msg => "Failed to load configuration");
    }
    my $config = $fnret->value;
    if (!$config->{'portForwardingEnabled'}) {
        return R('ERR_FORBIDDEN', msg => "Port forwarding feature is disabled on this bastion");
    }

    my $remote_user  = $params{'remote_user'};     # can be undef for a user-wildcard
    my $remote_ip    = $params{'remote_ip'};       # mandatory
    my $ssh_port     = $params{'ssh_port'};        # SSH server port (default 22)
    my $forward_port = $params{'forward_port'};    # Port to forward through the tunnel

    # For backward compatibility, also support remote_port parameter
    my $remote_port = $params{'remote_port'};      # can be undef for a port-wildcard

    my $way     = $params{'way'};                  # group, groupguest, personal
    my $group   = $params{'group'};                # only for way=group or way=groupguest (needs to be shortGroup!)
    my $account = $params{'account'};              # only for way=personal or way=groupguest

    my $exactMatch = $params{'exactMatch'};        # if true, look for the EXACT access we want, don't do any wildcarding

    # no input validation here as this is called by trusted functions that have already validated the inputs

    my $file;
    my $remoteaccount;
    my $prefix = "allowed";

    if ($way eq 'personal') {
        $fnret =
          OVH::Bastion::is_bastion_account_valid_and_existing(account => $account, accountType => 'normal', cache => 1);
        $fnret or return $fnret;
        my $sysaccount = $fnret->value->{'sysaccount'};
        $remoteaccount = $fnret->value->{'remoteaccount'};
        $prefix        = $remoteaccount ? "allowed_$remoteaccount" : "allowed";
        $file          = "/home/allowkeeper/$sysaccount/$prefix.forward";
    }
    elsif ($way eq 'group') {
        $fnret = OVH::Bastion::is_valid_group_and_existing(group => $group, groupType => 'key', cache => 1);
        $fnret or return $fnret;
        my $sysgroup = $fnret->value->{'group'};
        $file = "/home/$sysgroup/allowed.forward";
    }
    elsif ($way eq 'groupguest') {
        $fnret =
          OVH::Bastion::is_bastion_account_valid_and_existing(account => $account, accountType => 'normal', cache => 1);
        $fnret or return $fnret;
        my $sysaccount = $fnret->value->{'sysaccount'};
        $remoteaccount = $fnret->value->{'remoteaccount'};
        $prefix        = $remoteaccount ? "allowed_$remoteaccount" : "allowed";
        $file          = "/home/allowkeeper/$sysaccount/$prefix.partial.$group.forward";
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Invalid way '$way'");
    }
    return R('KO_ACCESS_DENIED', silent => 1) if !-r $file;
    if (open(my $fh, '<', $file)) {
        while (my $line = <$fh>) {
            chomp $line;
            next if $line =~ /^\s*#/;    # skip commented lines
            next if $line =~ /^\s*$/;    # skip empty lines

            # parse: remote_ip:ssh_port:forward_port:remote_user:local_port:rule_id [comment]
            if ($line =~ m{^(\[[^\]]+\]|[^:]+):([^:]*):([^:]*):([^:]*):([^:]*):([^:\s]*)\s*(?:#.*)?$}) {
                my (
                    $file_remote_ip,   $file_ssh_port,   $file_forward_port,
                    $file_remote_user, $file_local_port, $file_rule_id
                ) = ($1, $2, $3, $4, $5, $6);

                # remove brackets from IPv6 addresses
                $file_remote_ip =~ s/^\[|\]$//g;

                # handle wildcards
                $file_ssh_port     = undef if $file_ssh_port eq '*';
                $file_forward_port = undef if $file_forward_port eq '*';
                $file_remote_user  = undef if $file_remote_user eq '*';

                print "DEBUG: checking line '$line' -> ip='$file_remote_ip', ssh_port='"
                  . (defined $file_ssh_port ? $file_ssh_port : '<any>')
                  . "', forward_port='"
                  . (defined $file_forward_port ? $file_forward_port : '<any>')
                  . "', user='"
                  . (defined $file_remote_user ? $file_remote_user : '<any>') . "'\n"
                  if osh_debug();

                if ($exactMatch) {
                    # exact match required - compare ssh_port and forward_port
                    if (   ($file_remote_ip eq $remote_ip)
                        && (($file_ssh_port     // '') eq ($ssh_port     // ''))
                        && (($file_forward_port // '') eq ($forward_port // ''))
                        && (($file_remote_user  // '') eq ($remote_user  // '')))
                    {
                        close($fh);
                        return R('OK', value => {file => $file, line => $line});
                    }
                }
                else {
                    # check if the requested access matches this line (with wildcards)
                    my $ip_match       = _check_ip_match($remote_ip, $file_remote_ip);
                    my $ssh_port_match = (!defined $file_ssh_port || !defined $ssh_port || $file_ssh_port eq $ssh_port);
                    my $forward_port_match =
                      (!defined $file_forward_port || !defined $forward_port || $file_forward_port eq $forward_port);
                    my $user_match =
                      (!defined $file_remote_user || !defined $remote_user || $file_remote_user eq $remote_user);

                    # For backward compatibility, also check remote_port if provided
                    my $remote_port_match = 1;
                    if (defined $remote_port) {
                        $remote_port_match = (!defined $file_ssh_port || $file_ssh_port eq $remote_port);
                    }

                    if ($ip_match && $ssh_port_match && $forward_port_match && $user_match && $remote_port_match) {
                        close($fh);
                        return R(
                            'OK',
                            value => {
                                file         => $file,
                                line         => $line,
                                ip           => $file_remote_ip,
                                ssh_port     => $file_ssh_port,
                                forward_port => $file_forward_port,
                                user         => $file_remote_user
                            }
                        );
                    }
                }
            }
        }
        close($fh);
    }

    return R('KO_ACCESS_DENIED', silent => 1);
}

# Helper function to check if an IP matches (including subnet matching)
sub _check_ip_match {
    my ($requested_ip, $allowed_ip) = @_;

    return 0 if !defined $requested_ip || !defined $allowed_ip;

    # exact match
    return 1 if $requested_ip eq $allowed_ip;

    # check if allowed_ip is a subnet and requested_ip falls within it
    my $fnret = OVH::Bastion::is_valid_ip(ip => $allowed_ip, allowSubnets => 1);
    if ($fnret && $fnret->value->{'type'} eq 'subnet') {
        # Parse the allowed subnet
        my $allowed_net = eval { require Net::IP; Net::IP->new($allowed_ip); };
        return 0 if !$allowed_net;

        # Check if requested IP is in the subnet
        my $requested_net = eval { Net::IP->new($requested_ip); };
        return 0 if !$requested_net;

        return $requested_net->overlaps($allowed_net) == $Net::IP::IP_B_IN_A_OVERLAP;
    }

    return 0;
}

# Get all port forwarding accesses for an account
sub get_portforward_acls {
    my %params  = @_;
    my $account = $params{'account'};

    # Check if port forwarding is enabled in configuration
    my $fnret = OVH::Bastion::load_configuration();
    if (!$fnret) {
        return R('ERR_CONFIGURATION', msg => "Failed to load configuration");
    }
    my $config = $fnret->value;
    if (!$config->{'portForwardingEnabled'}) {
        return R('ERR_FORBIDDEN', msg => "Port forwarding feature is disabled on this bastion");
    }

    my @acls;

    $fnret = OVH::Bastion::is_bastion_account_valid_and_existing(account => $account);
    $fnret or return $fnret;

    $account = $fnret->value->{'account'};
    my $sysaccount = $fnret->value->{'sysaccount'};

    # 1/3 check for personal port forwarding accesses
    my $grantedPersonal = OVH::Bastion::get_portforward_acl_way(way => 'personal', account => $account);
    push @acls, {type => 'personal', acl => $grantedPersonal->value}
      if ($grantedPersonal && @{$grantedPersonal->value || []});

    # 2/3 check for group port forwarding accesses (by being a member)
    $fnret = OVH::Bastion::get_user_groups(account => $account, groupType => 'key');
    if ($fnret) {
        foreach my $groupHashRef (@{$fnret->value}) {
            my $group      = $groupHashRef->{'group'};
            my $shortGroup = $group;
            $shortGroup =~ s/^key//;
            my $grantedGroupViaMembership = OVH::Bastion::get_portforward_acl_way(way => 'group', group => $shortGroup);
            if ($grantedGroupViaMembership && @{$grantedGroupViaMembership->value || []}) {
                push @acls,
                  {
                    type  => 'group-member',
                    group => $shortGroup,
                    acl   => $grantedGroupViaMembership->value
                  };
            }
        }
    }

    # 3/3 check for group port forwarding accesses (by being a guest)
    $fnret = OVH::Bastion::get_user_groups(account => $account, groupType => 'key');
    if ($fnret) {
        foreach my $groupHashRef (@{$fnret->value}) {
            my $group      = $groupHashRef->{'group'};
            my $shortGroup = $group;
            $shortGroup =~ s/^key//;
            my $grantedGroupViaGuest =
              OVH::Bastion::get_portforward_acl_way(way => 'groupguest', group => $shortGroup, account => $account);
            if ($grantedGroupViaGuest && @{$grantedGroupViaGuest->value || []}) {
                push @acls,
                  {
                    type  => 'group-guest',
                    group => $shortGroup,
                    acl   => $grantedGroupViaGuest->value
                  };
            }
        }
    }

    return R('OK', value => \@acls);
}

# Read port forwarding rules from a file
sub get_port_forwards_from_file {
    my %params = @_;
    my $file   = $params{'file'};

    return R('ERR_MISSING_PARAMETER', msg => "Missing file parameter")         unless $file;
    return R('ERR_FILE_NOT_FOUND',    msg => "File not found or not readable") unless -r $file;

    my @rules = ();

    if (open(my $fh, '<', $file)) {
        while (my $line = <$fh>) {
            chomp $line;
            next if $line =~ /^\s*#/;    # skip commented lines
            next if $line =~ /^\s*$/;    # skip empty lines

            # parse: remote_ip:ssh_port:forward_port:remote_user:local_port:rule_id [comment]
            if ($line =~ m{^(\[[^\]]+\]|[^:]+):([^:]*):([^:]*):([^:]*):([^:]*):([^:\s]*)\s*(?:#\s*(.*))?$}) {
                my ($remote_ip, $ssh_port, $forward_port, $remote_user, $local_port, $rule_id, $comment_part) =
                    ($1, $2, $3, $4, $5, $6, $7);

                # remove brackets from IPv6 addresses
                $remote_ip =~ s/^\[|\]$//g;

                # handle wildcards
                $ssh_port     = undef if $ssh_port eq '*';
                $forward_port = undef if $forward_port eq '*';
                $remote_user  = undef if $remote_user eq '*';

                my %entry = (
                    remote_ip    => $remote_ip,
                    ssh_port     => $ssh_port,
                    forward_port => $forward_port,
                    remote_user  => $remote_user,
                    local_port   => $local_port,
                    rule_id      => $rule_id,
                );

                # Parse additional info from comments
                if ($comment_part) {
                    if ($comment_part =~ /COMMENT=<([^>]+)>/) {
                        $entry{'comment'} = $1;
                    }
                    if ($comment_part =~ /EXPIRY=(\d+)/) {
                        $entry{'expiry'} = $1;
                    }
                    if ($comment_part =~ /FORCEKEY=(\S+)/) {
                        $entry{'force_key'} = $1;
                    }
                    if ($comment_part =~ /FORCEPASSWORD=(\S+)/) {
                        $entry{'force_password'} = $1;
                    }
                }

                push @rules, \%entry;
            }
        }
        close($fh);
    }
    else {
        return R('ERR_CANNOT_OPEN_FILE', msg => "Cannot open file $file: $!");
    }

    return R('OK', value => \@rules);
}

# Get port forwarding ACL in a specific way
sub get_portforward_acl_way {
    my %params  = @_;
    my $way     = $params{'way'};        # group, groupguest, personal
    my $group   = $params{'group'};      # only for way=group or way=groupguest (needs to be shortGroup!)
    my $account = $params{'account'};    # only for way=personal or way=groupguest

    my $fnret;

    if ($way eq 'personal') {
        $fnret =
          OVH::Bastion::is_bastion_account_valid_and_existing(account => $account, accountType => 'normal', cache => 1);
        $fnret or return $fnret;
        my $sysaccount    = $fnret->value->{'sysaccount'};
        my $remoteaccount = $fnret->value->{'remoteaccount'};
        my $prefix        = $remoteaccount ? "allowed_$remoteaccount" : "allowed";
        $fnret =
          OVH::Bastion::get_portforward_acl_way_from_file(file => "/home/allowkeeper/$sysaccount/$prefix.forward");
    }
    elsif ($way eq 'group') {
        $fnret = OVH::Bastion::is_valid_group_and_existing(group => $group, groupType => 'key', cache => 1);
        $fnret or return $fnret;
        my $sysgroup = $fnret->value->{'group'};
        $fnret = OVH::Bastion::get_portforward_acl_way_from_file(file => "/home/$sysgroup/allowed.forward");
    }
    elsif ($way eq 'groupguest') {
        $fnret =
          OVH::Bastion::is_bastion_account_valid_and_existing(account => $account, accountType => 'normal', cache => 1);
        $fnret or return $fnret;
        my $sysaccount    = $fnret->value->{'sysaccount'};
        my $remoteaccount = $fnret->value->{'remoteaccount'};
        my $prefix        = $remoteaccount ? "allowed_$remoteaccount" : "allowed";
        $fnret = OVH::Bastion::get_portforward_acl_way_from_file(
            file => "/home/allowkeeper/$sysaccount/$prefix.partial.$group.forward");
    }
    else {
        return R('ERR_INVALID_PARAMETER', msg => "Invalid way '$way'");
    }

    return $fnret;
}

# Parse a port forwarding ACL file and return structured data
sub get_portforward_acl_way_from_file {
    my %params = @_;
    my $file   = $params{'file'};

    return R('OK', value => []) if !-r $file;

    my @result;
    if (open(my $fh, '<', $file)) {
        while (my $line = <$fh>) {
            chomp $line;
            next if $line =~ /^\s*#/;    # skip commented lines
            next if $line =~ /^\s*$/;    # skip empty lines

            # parse: remote_ip:ssh_port:forward_port:remote_user:local_port:rule_id [comment]
            if ($line =~ m{^(\[[^\]]+\]|[^:]+):([^:]*):([^:]*):([^:]*):([^:]*):([^:\s]*)\s*(?:#\s*(.*))?$}) {
                my ($remote_ip, $ssh_port, $forward_port, $remote_user, $local_port, $rule_id, $comment_part) =
                  ($1, $2, $3, $4, $5, $6, $7);

                # remove brackets from IPv6 addresses
                $remote_ip =~ s/^\[|\]$//g;

                # handle wildcards
                $ssh_port     = undef if $ssh_port eq '*';
                $forward_port = undef if $forward_port eq '*';
                $remote_user  = undef if $remote_user eq '*';

                my %entry = (
                    remote_ip    => $remote_ip,
                    ssh_port     => $ssh_port,
                    forward_port => $forward_port,
                    remote_user  => $remote_user,
                    local_port   => $local_port,
                    rule_id      => $rule_id,
                );

                # parse comment for additional metadata
                if ($comment_part) {
                    if ($comment_part =~ /add by (\S+) on ([^#]+)/) {
                        $entry{'addedBy'}   = $1;
                        $entry{'addedDate'} = $2;
                    }
                    if ($comment_part =~ /TTL=([^#\s]+)/) {
                        $entry{'ttl'} = $1;
                    }
                    if ($comment_part =~ /COMMENT=<([^>]+)>/) {
                        $entry{'comment'} = $1;
                    }
                }

                push @result, \%entry;
            }
        }
        close($fh);
    }

    return R('OK', value => \@result);
}

sub print_portforward_acls {
    my %params   = @_;
    my $acls     = $params{'acls'} || [];
    my $reverse  = $params{'reverse'};
    my $includes = $params{'includes'} || [];
    my $excludes = $params{'excludes'} || [];

    my $includere = OVH::Bastion::build_re_from_wildcards(wildcards => $includes, implicit_contains => 1)->value;
    my $excludere = OVH::Bastion::build_re_from_wildcards(wildcards => $excludes, implicit_contains => 1)->value;

    # first, get all the rows we'll print, and fill both the array that will be printed (printRows),
    # and the one that will be returned as JSON (jsonRows). We also apply the filters here to include/exclude
    # the requested patterns, if any
    # also take this opportunity to remember the longest field for each column
    my @printRows;
    my @jsonRows;
    my @columnNames =
      qw( REMOTE-HOST SSH-PORT FORWARD-PORT REMOTE-USER LOCAL-PORT RULE-ID ACCESS-BY ADDED-BY ADDED-AT COMMENT);
    my @printColumnLength = map { length } @columnNames;

    foreach my $contextAcl (@$acls) {
        my $type  = $contextAcl->{'type'};
        my $group = $contextAcl->{'group'};
        my $acl   = $contextAcl->{'acl'};

        my $accessType = ($group ? "$group($type)" : $type);

      ENTRY: foreach my $entry (@$acl) {
            my $addedBy   = $entry->{'addedBy'}   || '-';
            my $addedDate = $entry->{'addedDate'} || '-';
            $addedDate = substr($addedDate, 0, 10) if $addedDate ne '-';
            my $comment = $entry->{'comment'} || '-';

            # resolve reverse if asked for it
            my $ipReverse;
            $ipReverse = OVH::Bastion::ip2host($entry->{'remote_ip'})->value if $reverse;
            $entry->{'reverseDns'} = $ipReverse;

            my @row = (
                $ipReverse ? $ipReverse : $entry->{'remote_ip'},
                $entry->{'ssh_port'}     || '*',
                $entry->{'forward_port'} || '*',
                $entry->{'remote_user'}  || '*',
                $entry->{'local_port'}   || '-',
                $entry->{'rule_id'}      || '-',
                $accessType,
                $addedBy,
                $addedDate,
                $comment
            );

            # if we have includes or excludes, match fields against the built regex
            # for excludes, any field matching is enough to exclude the row
            if ($excludere) {
                foreach (@row) {
                    next ENTRY if ($_ =~ $excludere);
                }
            }

            # for includes, at least one field must match or we exclude the row
            if ($includere) {
                my $matched = 0;
                foreach (@row) {
                    $matched++ if ($_ =~ $includere);
                    last       if $matched;
                }
                next ENTRY if !$matched;
            }

            # if we're here, row must be included
            push @printRows, \@row;
            push @jsonRows,  $entry;

            # for each cell of this row, remember its len if its longer than any previously seen cell in the same column
            for (0 .. @row) {
                my $cellLen = length($row[$_]);
                $printColumnLength[$_] = $cellLen if $printColumnLength[$_] < $cellLen;
            }
        }
    }

    # then, check if we have at least one non-empty row for each column,
    # so that we can omit the empty columns on print (empty cells are '-')
    my %atLeastOne;
    foreach my $row (@printRows) {
        my $i = 0;
        foreach my $cell (@$row) {
            $atLeastOne{$i}++ if $cell ne '-';
            $i++;
        }
    }

    # now build the header
    my (@header, @format, @underline);
    my $i = 0;
    foreach (@columnNames) {
        if ($atLeastOne{$i}) {
            push @header,    $_;
            push @format,    "%" . ($printColumnLength[$i] + 0) . "s";
            push @underline, "-" x ($printColumnLength[$i] + 0);
        }
        $i++;
    }
    my $formatstr = join(" ", @format);
    osh_info(sprintf($formatstr, @header));
    osh_info(sprintf($formatstr, @underline));

    # and print each row, potentially omitting empty columns (%atLeastOne)
    foreach my $row (@printRows) {
        my @fields;
        $i = 0;
        foreach my $cell (@$row) {
            push @fields, $cell if ($atLeastOne{$i});
            $i++;
        }
        osh_info(sprintf($formatstr, @fields));
    }

    return R('OK', value => \@jsonRows);
}

1;
