Better to use a unix/linux system to not deal with some Windows issues specially when using Celery (you need eventlet), and when using lib-magic (you'll need lib-magic-bin) and you'll have to respect the specified version so as not to face troubles while running the app.
Install:
Redis servier 3.2.1 
Celery 4.2.1 
Django 

To start the app first migrate models to database (if you didn't): 
makemigrations
migrate


Start Django server:

python manage.py runserver

Start Redis Server.


Run these commands in Redis-cli:

CONFIG SET dir "C:/Users/INSPIRON15/Documents/write_redis"
CONFIG SET dbfilename temp.rdb
BGSAVE 

Run Celery :
celery -A WS_VulnS worker -P eventlet -c 1000

(if linux: run this command without eventlet)