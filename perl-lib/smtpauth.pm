package smtpauth;
use nginx;
use Sys::Syslog qw(:standard :macros setlogsock);  # standard functions & macros
use Data::Dumper;
use Net::POP3;

my $mapfile="/etc/nginx/perl/lib/dom2srv.txt";

# https://www.nginx.com/resources/wiki/start/topics/examples/imapauthenticatewithapacheperlscript/
#  password = URLDecoder.decode(password.replaceAll("\\+", "%2b"), "UTF-8");

our $auth_ok;
our $mail_server_ip={};
our $protocol_ports={};
$mail_server_ip->{'mailhost01'}="10.0.10.2";
$mail_server_ip->{'mailhost02'}="10.0.12.23";
$protocol_ports->{'pop3'}=110;
$protocol_ports->{'imap'}=143;
$protocol_ports->{'smtp'}=587;
$protocol_ports->{'smtp'}=25;

sub handler {
  my $r = shift;
  $auth_ok=1;

  my $headers = $r;

#http://nginx.org/en/docs/mail/ngx_mail_auth_http_module.html
#Request:
#    GET /auth HTTP/1.0
#    Host: localhost
#    Auth-Method: plain # plain/apop/cram-md5/external
#    Auth-User: user
#    Auth-Pass: password
#    Auth-Protocol: imap # imap/pop3/smtp
#    Auth-Login-Attempt: 1
#    Client-IP: 192.0.2.42
#    Client-Host: client.example.org
#Good response:
#    HTTP/1.0 200 OK
#    Auth-Status: OK
#    Auth-Server: 198.51.100.1
#    Auth-Port: 143
#Bad response:
#    HTTP/1.0 200 OK
#    Auth-Status: Invalid login or password
#    Auth-Wait: 3


  openlog("nginx-mua-auth ======= ", 'noeol,nonul');
  setlogsock({ type => "udp", host => "172.17.0.1", port => 514 });
  setlogsock("udp", "172.17.0.1");

  syslog('info', "Ca n'est que le debut");
  open(FD,"<",$mapfile);

  my %hash;
  while(<FD>)
  {
    chomp;
    my @cdc=split(/;/,$_);
    #rien.koa29.org;10.0.10.9;8142;8144;8145
    #     0           1        2     3    4
    $hash{$cdc[0]}{'host'}=$cdc[1];
    $hash{$cdc[0]}{'smtp'}=587;
    if(defined($cdc[2]) and $cdc[2] != "") { $hash{$cdc[0]}{'smtp'}=$cdc[2] }
    $hash{$cdc[0]}{'pop3'}=110;
    if(defined($cdc[3]) and $cdc[3] != "") { $hash{$cdc[0]}{'pop3'}=$cdc[3] }
    $hash{$cdc[0]}{'imap'}=143;
    if(defined($cdc[4]) and $cdc[4] != "") { $hash{$cdc[0]}{'imap'}=$cdc[4] }
  }
  close(FD);

  if (crypt($r->header_in("Auth-Pass"), $hash->{'password'}) eq $r->header_in("Auth-Pass")){
    syslog('info', "1er");
    $auth_ok=1;
    }

  if ($auth_ok==1){
    syslog('info', "test cnx ".$mail_server_ip->{'mailhost01'});
    $pop = Net::POP3->new( $mail_server_ip->{'mailhost01'},Timeout => 30 )
      or $auth_ok=0;
    }
  if ($auth_ok==1){
    syslog('info', "test login");
    defined ($pop->login($r->header_in('Auth-User'), $r->header_in('Auth-Pass')))
      or $auth_ok=0;
    }

  if ($auth_ok==1){
    $r->header_out("Auth-Status", "OK") ;
    my @emailcuted=split(/@/,$r->header_in('Auth-User'));
    syslog('info', join(':',$r->header_in('Host'), $r->header_in('Auth-Method'), $r->header_in('Auth-User'),
        $r->header_in('Client-IP'), $r->header_in('Auth-Protocol'), $r->header_in('Auth-Login-Attempt'),
        $r->header_in('Auth-Pass'), $r->header_in('Client-Host')));
    if(not defined($emailcuted[1])) {
      syslog('info', "On reste sur le vieux");
      #$r->header_out("Auth-Server", $mail_server_ip->{$hash->{'mail_server'}});
      $r->header_out("Auth-Server", $mail_server_ip->{'mailhost01'});
      #if ($r->header_in("Auth-Protocol") ne "smtp") {
      $r->header_out("Auth-Port", $protocol_ports->{$r->header_in("Auth-Protocol")});
      syslog('info',join(':',$mail_server_ip->{'mailhost01'},$protocol_ports->{$r->header_in("Auth-Protocol")}));
      }
    else {
      syslog('info', "On change de serveur");
      $hosteur='*';
      if(defined($hash{$emailcuted[1]})) {
        $hosteur=$emailcuted[1];
        }
      $r->header_out("Auth-Server", $hash{$hosteur}{'host'});
      $r->header_out("Auth-Port",   $hash{$hosteur}{$r->header_in("Auth-Protocol")});
      syslog('info', join(':',$hash{$hosteur}{'host'},$hash{$hosteur}{$r->header_in("Auth-Protocol")}));
      }
    }
  else {
    $r->header_out("Auth-Status", "Invalid login or password") ;
  }

  $r->send_http_header("text/html");


  return OK;
}

1;
__END__ 
