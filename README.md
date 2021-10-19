# Guardicore AD Labeler

Labels assets in Guardicore based on their AD group membership or OU membership.

## Future Features

- [ ] Continuous labeling
- [ ] Per rule labeling interval

## Usage

1. clone the repository `git clone git@github.com:n3tsurge/gc-ad-labeler.git`
2. Install the dependencies `pipenv install`
3. Setup your labeling rules in `config.yml`
4. Run `pipenv run python gc-ad-labeler.py`

```bash
$ pipenv run python gc-ad-labeler.py -h
usage: gc-ad-labeler.py [-h] [--config CONFIG]
                        [--gc-management-url GC_MANAGEMENT_URL] [-u USER] [-p]

optional arguments:
  -h, --help            show this help message and exit
  --config CONFIG       The path to the configuration file
  --gc-management-url GC_MANAGEMENT_URL
                        Guardicore management URL
  -u USER, --user USER  Guardicore username
  -p, --password        Prompt for the Guardicore password
```

## Labeling Rules

```yaml
rules:
  label-domain-admin-computers:
    target_dn: OU=Admins,OU=Workstations,DC=contoso,DC=com
    domain: contoso.com
    labels:
      Active Directory Admin: 'Yes'
```
