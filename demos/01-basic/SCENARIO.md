# Demo 01 - Basic attack path mapping

A small but realistic Active Directory slice modeled after a BloodHound
collection. The attacker has phished a single low-privilege workstation
user and wants to reach **Domain Admins**.

## Environment

- `JDOE@CORP.LOCAL` - phished user (attacker foothold / `owned`)
- `HELPDESK@CORP.LOCAL` - helpdesk group JDOE belongs to
- `WS01.CORP.LOCAL` - workstation, helpdesk is local admin
- `SVC_BACKUP@CORP.LOCAL` - service account with a live session on WS01
- `TIER1ADMINS@CORP.LOCAL` - the service account can reset its members
- `DOMAIN ADMINS@CORP.LOCAL` - **high value target**
- `CORP.LOCAL` - the domain object (DCSync target)

## The path REDPATH should find

```
JDOE -[MemberOf]-> HELPDESK -[AdminTo]-> WS01
     -[HasSession]-> SVC_BACKUP -[ForceChangePassword]-> TIER1ADMINS
     -[MemberOf]-> DOMAIN ADMINS
```

This is the minimum-cost route. The `HasSession` edge from WS01 to
SVC_BACKUP is the chokepoint: clearing that session (or isolating WS01)
breaks the only path to Domain Admins.

## Run it

```
python -m redpath paths demos/01-basic/corp.json
python -m redpath remediate demos/01-basic/corp.json --format json
```
