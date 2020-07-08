# Carbon Black EDR - Lastline Connector

NOTE: This connector integrates the Carbon Black EDR product with LastLine.  Integration
with Carbon Black Cloud products, including "NGAV" and "Enterprise EDR" is not included here.

The LastLine connector submits binaries collected by the Carbon Black EDR to a LastLine
appliance for binary analysis. The results are collected and placed into an Intelligence
Feed on your Carbon Black EDR server. The feed will then tag any binaries executed on your
endpoints identified as malware by LastLine. Only binaries submitted by the connector
for analysis will be included in the generated Intelligence Feed.

## Installation Quickstart

As root on your Carbon Black EDR or other RPM based 64-bit Linux distribution server:
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

## Support

1. Use the [Developer Community Forum](https://community.carbonblack.com/t5/Developer-Relations/bd-p/developer-relations) to discuss issues and ideas with other API developers in the Carbon Black Community.
2. Report bugs and change requests through the GitHub issue tracker. Click on the + sign menu on the upper right of the screen and select New issue. You can also go to the Issues menu across the top of the page and click on New issue.
3. View all API and integration offerings on the [Developer Network](https://developer.carbonblack.com/) along with reference documentation, video tutorials, and how-to guides.
