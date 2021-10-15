# LoginPage_using_Elliptic_curve_cryptography-
This is a webpage that contains login and signup page by which the password is stored using elliptic curve cryptography and then again hashed using sha-256

The technologies used for this are Python, HTML, CSS, Flask, MySQL, Elliptic curve cryptography, sha-256
elliptic curve used: "secp192r1" => y^2 = x^3 + 6277101735386680763835789423207666416083908700390324961276x + 2455155546008943817740293915197451784769108058161191238065 (mod 6277101735386680763835789423207666416083908700390324961279)



packages needed: anaconda, pytorch, flask,flask_mysqldb,tinyec, hashlib,binascii,passlib.hash, xampp. install all the above packages

after installing al the above packages, 
step-1: open xampp and start apache, Mysql server

step-2: create a database with name 'ecaf'

step-3: create a table 'users' with attributes 'username' (VARCHAR with size 200), 'password' (VARCHAR with size 200) , dob (VARCHAR with size 200)

step-4: open anaconda prompt and go to the project directory

step-5: enter python server.py.

step-6: Now open web browser and enter 127.0.0.1:5000/login. This will redirect to the login page. User needs to be registered before logging in .

![image](https://user-images.githubusercontent.com/57107143/137546922-43217649-357b-4f01-89ab-f28bd5f3f21f.png)

![image](https://user-images.githubusercontent.com/57107143/137547202-8fbd8d4d-bd7e-4ecd-8889-f399ba7fe1ca.png)

