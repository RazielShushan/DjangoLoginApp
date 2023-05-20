# DjangoLoginApp - Communication System
This application was built as a submission project for the 'Computer Security' course at HIT College. It is a Django-based application that utilizes VS Code as the development environment and MySQL as the database.
## Prerequisites
Before running the application, ensure that you have the following set up:
- Python
- Django
- MySQL
- Virtual environment (recommended)

## Installation
1. Clone the repository to your local machine.
2. Create a virtual environment (optional but recommended).
3. Activate the virtual environment.
4. Install the required packages by running the following command:

```python 
pip install -r requirements.txt;
```

## Database Configuration
1. Create a MySQL database named 'communication_system'.
2. Update the database configuration in the 'settings.py' file of the project
```python 
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'communication_system',
        'USER': '<your_mysql_user>',
        'PASSWORD': '<your_mysql_password>',
        'HOST': 'localhost',
        'PORT': '3306',
    }
}
```
## Database Migration
1. Apply the database migration by running the following commands:
```python 
python manage.py makemigrations
python manage.py migrate
```

## Running the Application
### With SSL
Before running the application with SSL, you need to generate a local certificate and create the **cert.pem** and **key.pem** files. Follow the steps below to generate the certificate:
1. Open a command prompt or terminal.
2. Navigate to the project directory.
3. Run the following command to generate the certificate and key files:
```cmd 
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout key.pem -out cert.pem
```
Now, use the following command:
```python 
python manage.py runsslserver --certificate cert.pem --key key.pem
```
### Without SSL
To run the application with HTTP (unsecured), use the following command:
```python 
python manage.py runserver
```
# Application Overview
This application was developed by the following programmers:

- [Raziel Shushan](https://github.com/RazielShushan).
- [Almog Franco](https://github.com/Almog-Fr).
- [Alon Bril](https://github.com/alonbril).
- [Netanel Hajbi](https://github.com/netanelhaj).
- [Ori Ronen](https://github.com/orironen555).

This application implements various security measures learned during the 'Computer Security' course at HIT College. It covers topics such as writing secure code, protecting against SQL injection and XSS attacks, and utilizing cryptography.

The project has two branches:
1. **master** - A secure version of the application with implemented protections against attacks.
2. **vulnerable-version** - A version exposed to SQL injection (SQLI) and cross-site scripting (XSS) vulnerabilities.


