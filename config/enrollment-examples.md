# Agent enrollment examples

Place the enrollment block inside the existing `<client>` section of each agent's
`ossec.conf`. Do not create a second `<client>` section. Do not publish the `<server>`
section, because it contains the manager address.

## SRV-DC01 (domain controller)

Windows path: `C:\Program Files (x86)\ossec-agent\ossec.conf`

```xml
<client>
  <enrollment>
    <enabled>yes</enabled>
    <agent_name>SRV-DC01</agent_name>
    <groups>windows-servers</groups>
  </enrollment>
  ...
</client>
```

## WC01 (Windows 11 client)

```xml
<client>
  <enrollment>
    <enabled>yes</enabled>
    <agent_name>WC01</agent_name>
    <groups>windows-clients</groups>
  </enrollment>
  ...
</client>
```

## Pi-hole01 (Debian container)

Linux path: `/var/ossec/etc/ossec.conf`

```xml
<client>
  <enrollment>
    <enabled>yes</enabled>
    <agent_name>Pi-hole01</agent_name>
    <groups>DNS</groups>
  </enrollment>
  ...
</client>
```

## Pi-hole log source (Pi-hole01 only, inside <ossec_config>)

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/pihole/pihole.log</location>
</localfile>
```

## Validate after editing (Pi-hole01)

```bash
(echo "<root>"; cat /var/ossec/etc/ossec.conf; echo "</root>") | xmllint --noout - && echo OK
```
