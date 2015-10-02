# Carbon Black - Lastline Connector

## Installation Quickstart

As root on your Carbon Black or other RPM based 64-bit Linux distribution server:
```
cd /etc/yum.repos.d
curl -O https://opensource.carbonblack.com/release/x86_64/CbOpenSource.repo
yum install python-cb-lastline-connector
```

Once the software is installed via YUM, copy the `/etc/cb/integrations/lastline/connector.conf.example` file to
`/etc/cb/integrations/lastline/connector.conf`. Edit this file and place your Carbon Black API key into the
`carbonblack_server_token` variable and your Carbon Black server's base URL into the `carbonblack_server_url` variable.

Then you must place your credentials for LastLine into the configuration file: place your API key and API token
respectively into the `lastline_api_key` and `lastline_api_token` variables in the 
`/etc/cb/integrations/lastline/connector.conf` file.

If you are using an on-premise LastLine appliance, make sure to place the URL for your on-premise LastLine appliance
in the `lastline_url` variable and set `lastline_url_sslverify` to `0` if your appliance does not have a valid SSL
certificate.

Any errors will be logged into `/var/log/cb/integrations/lastline/lastline.log`.

## Troubleshooting

If you suspect a problem, please first look at the Lastline connector logs found here:
`/var/log/cb/integrations/lastline/lastline.log`
(There might be multiple files as the logger "rolls over" when the log file hits a certain size).

If you want to re-run the analysis across your binaries:

1. Stop the service: `service cb-lastline-connector stop`
2. Remove the database file: `rm /usr/share/cb/integrations/lastline/db/sqlite.db`
3. Remove the feed from your Cb server's Threat Intelligence page
4. Restart the service: `service cb-lastline-connector start`

## Contacting Bit9 Developer Relations Support

Web: https://community.bit9.com/groups/developer-relations
E-mail: dev-support@bit9.com

### Reporting Problems

When you contact Bit9 Developer Relations Technical Support with an issue, please provide the following:

* Your name, company name, telephone number, and e-mail address
* Product name/version, CB Server version, CB Sensor version
* Hardware configuration of the Carbon Black Server or computer (processor, memory, and RAM)
* For documentation issues, specify the version of the manual you are using.
* Action causing the problem, error message returned, and event log output (as appropriate)
* Problem severity
