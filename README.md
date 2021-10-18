<h1 align=center>CS3006 - Network Security & Cryptography Assignment</h1>

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisits](#prerequisits)
3. [File structure](#file-structure)
4. [Implementation](#implementation)
5. [Code Execution](#execution)
6. [References](#references)

## Overview

<p>A client-server application with confidential message exchange to provide authentication, integrity and key sharing among both the client and server with the help of RSA and Simplified AES algorithm.</p>

## Prerequisits

The code execution requires [python 3.x](https://www.python.org/) version installed on the system.

## File Structure

This repository consists of 2 files and 1 package which consists of 4 modules.

1. Util Package

   - _This utitlity package contains all the required files for performing entire encryption and decryption._

   - **The modules are:**

     - [RSA.py](#RSA)
     - [SAES.py](#saes.py)
     - [HashAlgo.py](#hashalgo.py)
     - [Operations.py](#operations.py)

2. [server.py](#server.py)

   - _This file is for server side communication & decryption algorithm implementation_

3. [client.py](#client.py)
   - _This file is for client side communication & encryption algorithm implementation_

## Implementation

---

### 1. RSA.py

_RSA class for generating private and public key and rsa encryption and algorithm_
