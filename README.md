# DRF 2geda

A Django app that provides a RESTful API interface for user registration and authentication using phone number or email.

## Basic Features

- Allows users to register using email or phone number.
- Email and Phone number verification.
- MailTrap integrated.
- Can set expiration time and length on generated tokens for phone verification.
- Google authentication.
- Password change and reset endpoints.

## Quick Start

Clone this repository to your local machine and rename the `.env.example` file found in the root directory of the project to `.env` and update the environment variables accordingly. Then you can start the project using Docker or manually using virtual environment.

1. Create a Python virtual environment and activate it.
2. Open up your terminal and run the following command to install the packages used in this project.

```
$ pip install -r requirements.txt
```

3. Run the following commands to setup the database tables and create a superuser.

```
$ python manage.py migrate
$ python manage.py createsuperuser
```

4. Run the development server using:

```
$ python manage.py runserver
```

5. Open a browser and go to http://localhost:8000/admin

