# CRM Application

This is a CRM (Customer Relationship Management) application built using Django, designed to help manage customer interactions, track leads, and organize customer data efficiently.

## Prerequisites

Before setting up the project, ensure you have the following installed:

- Python 3.x
- [Pipenv](https://pipenv.pypa.io/en/latest/) (for managing dependencies and virtual environments)
- Sqlite3 (or any other database compatible with Django)

## Setup Instructions

Follow these steps to get the CRM application up and running:

1. **Clone the Repository**  
   Clone this repository to your local machine using the following command:
   ```bash
   git clone https://github.com/your-repo/crm-app.git
   cd crm-app
   ```
2. **Install pipenv**
   ```bash
   pip install pipenv
   ```
3. **Activate Virtual Environment**
   ```bash
   pipenv shell
   ```
4. **Install Dependencies**
    ```bash
    pipenv install
    ```
5. **Apply Migrations**
    ```bash
    python manage.py migrate
    python manage.py loaddata db.sqlite3
    // admin password is rohit1234
    ```
6. **Apply Migrations**
    ```bash
    python manage.py runserver
    ```