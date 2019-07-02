1. Python version : 3.6

2. Install :
Redis Server 3.2.1 
Celery 4.2.1 
Django

3. To fix issues with the name "async" which is a keyword in Python 3 :
Rename "C:\Users\myusername\AppData\Local\Programs\Python\Python36-32\Lib\site-packages\celery\backends\async.py" to "C:\Users\myusername\AppData\Local\Programs\Python\Python36-32\Lib\site-packages\celery\backends\asynchronous.py"
Open redis.py and change every line that has the keyword "async" to "asynchronous".

4. To start the app first migrate models to database (if you didn't) (APP_NAME = WS_VulnS) : 
python APP_NAME makemigrations
python APP_NAME migrate

5. Start Django Server :
python manage.py runserver

6. Start Redis Server.

7. Run these commands in Redis-cli :
CONFIG SET stop-writes-on-bgsave-error no
CONFIG SET dir "C:/Path/To/A/RANDOM/DIRECTORY"
CONFIG SET dbfilename temp.rdb
BGSAVE

8. Run Celery (APP_NAME = WS_VulnS)
celery -A APP_NAME worker -c 1000

(If Windows : Run this command with -P eventlet)
