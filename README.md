# NginxMua

Take care :
  * This an working example (in my context)
  * This is my 1st version, with apparent password in log !!!!!!! (shoot it fast)
  * This is the result of a lot of research, and no author are congratulated :_(  (I applogies)

Subject:
  * I need an pop3/imap reverse proxy
  * I like perdition, but I love nginx

Future:
  * Integrate an soft "Fail2ban"
  * Redirection to imap/pop3 honeypot
  * Rewrite login by rules
  * Verify with multiple imap server :DDD

# How it's work ?
## Imap/pop3
  * The file concerned is conf.d/mail.conf
  * It present the ssl certificate and capability for each protocol
  * Do not use SMTP proxy of my config please
  * The auth_http parameter call (localy) an url 

## Http
  * The file concerned is conf.d/http.conf
  * This part create an http server with perl lib
  * The files requested for auth are there : perl-lib

## Files in perl-lib
  * Their job is to receive the auth request, and answer an law ;)


Okay this is an horriful doc, for an horriful config...
But any help are accepted ;)


Antoine.
