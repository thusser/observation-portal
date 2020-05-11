# Observation Portal
[![Build Status](https://travis-ci.com/observatorycontrolsystem/observation-portal.svg?branch=master)](https://travis-ci.com/observatorycontrolsystem/observation-portal)
[![Coverage Status](https://coveralls.io/repos/github/observatorycontrolsystem/observation-portal/badge.svg?branch=master)](https://coveralls.io/github/observatorycontrolsystem/observation-portal?branch=master)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/9846cee7c4904cae8864525101030169)](https://www.codacy.com/gh/observatorycontrolsystem/observation-portal?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=observatorycontrolsystem/observation-portal&amp;utm_campaign=Badge_Grade)
## An Astronomical Observation Web Portal and Backend

Within an observatory control system, the observation portal provides modules for:
- **Proposal management**: Calls for proposals, proposal creation, and time allocation
- **Request management**: Observation request validation, submission, and cancellation, and views providing ancillary information about them
- **Observation management**: Store and provide the telescope schedule, update observations, and update observation requests on observation update
- **User identity management**: Oauth2 authenticated user management that can be used in other applications

## Prerequisites
Optional prerequisites can be skipped for reduced functionality.

- Python >= 3.6
- PostgreSQL >= 9.6
- A running [Configuration Database](https://github.com/observatorycontrolsystem/configdb) 
- [Optional] A running [Downtime Database](https://github.com/observatorycontrolsystem/downtime)
- [Optional] A running Elasticsearch

## Environment Variables

|| Variable | Description | Default |
|-|----------|-------------|---------|
| General | DEBUG | Whether the application should run using Django's debug mode | `False` |
|| SECRET_KEY | The secret key used for sessions | *`random characters`* |
| Database | DB_NAME | The name of the database | `observation_portal` |
|| DB_USER | The database user  | `postgres` |
|| DB_PASSWORD | The database password | *`Empty string`* |
|| DB_HOST | The database host | `127.0.0.1` |
|| DB_PORT | The database port | `5432` |
| Cache | CACHE_BACKEND | The remote Django cache backend | `django.core.cache.backends.locmem.LocMemCache` |
|| CACHE_LOCATION | The cache location or connection string | `unique-snowflake` |
|| LOCAL_CACHE_BACKEND | The local Django cache backend to use | `django.core.cache.backends.locmem.LocMemCache` |
| Static and Media Files | AWS_BUCKET_NAME | The name of the AWS bucket in which to store static and media files | `observe.lco.global` |
|| AWS_REGION | The AWS region | `us-west-2` |
|| AWS_ACCESS_KEY_ID | The AWS user access key with read/write/permissions priveleges on the s3 bucket | `None` |
|| AWS_SECRET_ACCESS_KEY | The AWS user secret key to use with the access key | `None` |
|| MEDIA_STORAGE | The django media files storage backend | `django.core.files.storage.FileSystemStorage` |
|| MEDIAFILES_DIR | The directory in which to store media files | `media` |
|| STATIC_STORAGE | The Django static files storage backend | `django.contrib.staticfiles.storage.StaticFilesStorage` |
| Email | EMAIL_BACKEND | The Django SMTP backend to use | `django.core.mail.backends.console.EmailBackend` |
|| EMAIL_HOST | The SMTP host | `localhost` |
|| EMAIL_HOST_USER | The SMTP user | *`Empty string`* |
|| EMAIL_HOST_PASSWORD | The SMTP password | *`Empty string`* |
|| EMAIL_PORT | The SMTP port | `587` |
| External Services | CONFIGDB_URL | The url to the configuration database | `http://configdbdev.lco.gtn` |
|| DOWNTIMEDB_URL | The url to the downtime database | `http://downtimedb.lco.gtn` |
|| ELASTICSEARCH_URL | The url to the elasticsearch cluster | `http://elasticsearchdev.lco.gtn` |
| Task Scheduling | DRAMATIQ_BROKER_HOST | The broker host for dramatiq | `redis` |
|| DRAMATIQ_BROKER_PORT | The broker port for dramatiq | `6379` |

## Local Development

### **Set up external services**
Please refer to the [Configuration Database](https://github.com/observatorycontrolsystem/configdb) and [Downtime Database](https://github.com/LCOGT/downtime) projects for instructions on how to get those running, as well as the [Elasticsearch documentation](https://www.elastic.co/guide/en/elasticsearch/reference/5.6/install-elasticsearch.html) for options on how to run Elasticsearch.

### **Set up a [virtual environment](https://docs.python.org/3/tutorial/venv.html)**
Using a virtual environment is highly recommended. From the base of this project:
```
python3 -m venv ~/env
source ~/env/bin/activate
pip install numpy && pip install -r requirements.txt
```

### **Set up the database**
This example uses Docker to create a database. Make sure that the options that you use to set up your database correspond with the database settings in `observation_portal/settings.py`.

```
docker run --name observation-portal-postgres -e POSTGRES_PASSWORD=postgres -v/var/lib/postgresql/data -p5432:5432 -d postgres:11.1
docker exec -it observation-portal-postgres /bin/bash
createdb -U postgres -W observation_portal
exit
```

After creating the database, migrations must be applied to set up the tables in the database.

```
python manage.py migrate
```

### **Run the tests**
```
python manage.py test --settings=test_settings
```

### **Run the portal**

```
python manage.py runserver
```

The observation portal is now accessible from [http://127.0.0.1:8000](http://127.0.0.1:8000)!
