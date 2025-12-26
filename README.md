> <h2> ⛔️ <u>STOP</u>: DO NOT USE THIS REPOSITORY</h2>Fastkey is not ready yet, it's still cooking. Feel free to look around but do not try to use it, even for development. You have been warned.

# Fastkey 
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=99ccff) ![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi) ![JavaScript](https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&logo=javascript&logoColor=%23F7DF1E)

## Passkey Authentication for Python

This project is to enable developers to quickly implement Passkey credential managers into their application registration and login workflows.

I wrote this project as I found the existing projects lacking in clarity, or requiring registration or proprietary tools. Passkey Authentication should be simple and easy to implement.

This code uses asynchronous FastAPI however it is possible to place a wrapper around it for functions-framework implementations if you want to deploy the API as a Cloud Run Function.

## 1. Cloning

  ```powershell
  git clone https://github.com/dashasierra/fastkey.git
  ```

Then change into the fastkey project folder you just cloned:

  ```powershell
  cd fastkey
  ```

## 2. Run the Sample

The sample allows you to start an instance of Fastkey, register, and login using Passkeys.

### 2.1 Setup your Virtual Environment

These steps assume you are using venv. If this command fails, try installing `python3-venv`

  ```powershell
  python3 -m venv .venv
  ```

### 2.2 Activate the Virtual Environment

**Windows Users:**

  ```powershell
  .\.venv\Scripts\Activate.ps1
  ```

**Linux and macOS Users:**

  ```bash
  source .venv/bin/activate
  ```

### 2.3 Install requirements

We're installing the required dependencies, and sample dependencies which installs Uvicorn.

  ```powershell
  pip install -e .[sample]
  ```

### 2.3.a Environment Variables

| Variable      | Meaning                                                                 |
|---------------|-------------------------------------------------------------------------|
| HOSTNAME      | Hostname to align javascript and backend. e.g: `"https://mydomain.com"` |
| HOST_HEADER   | Defaults to "host" header. Set to "x-forwarded-host" if behind a proxy. |


### 2.4 Run the Sample Application

  ```powershell
  uvicorn --host 0.0.0.0 --port 8000 sample:app
  ```

You should now be able to access the application from http://localhost:8000/
