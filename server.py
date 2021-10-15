from flask import Flask,render_template,request,redirect
from flask_mysqldb import MySQL
from tinyec import registry
import hashlib
import binascii
import os
from passlib.hash import pbkdf2_sha256

app=Flask(__name__)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD']= ''
app.config['MYSQL_DB'] = 'ecaf'

mysql = MySQL(app)

def ECC(name,password,dob):
    #curve: "secp192r1" => y^2 = x^3 + 6277101735386680763835789423207666416083908700390324961276x + 2455155546008943817740293915197451784769108058161191238065 (mod 6277101735386680763835789423207666416083908700390324961279)
    curve = registry.get_curve('secp192r1')
    privKey=0
    #private key is sum of ascii values 
    for character in name:
        privKey+=ord(character)
    for character in password:
        privKey+=ord(character)    
    #get public key by multiplying private key and generating point
    pubKey = privKey * curve.g
    #multiplying x coordinate of public key with date of birth of user
    store=pubKey.x*int(dob[:2])
    #converting into hexadecimal 
    store=hex(store)
    return store
    
    
def hash_password(password):
    hash = pbkdf2_sha256.hash(password, rounds=20000, salt_size=16)
    return hash

@app.route('/login',methods=['GET'])
def home():
    return render_template('index.html')
    
@app.route('/register',methods=['GET'])
def register():
    return render_template('register.html') 


@app.route('/login_status',methods=['POST'])
def predict():
    username=request.form['username']
    password=request.form['password']
    if(username=="" or password==""):
        fetchdata="PLEASE FILL ALL THE DETAILS...."
        return render_template('index.html',data=fetchdata)
    else:      
        cur = mysql.connection.cursor()
        cur.execute('SELECT dob FROM users WHERE username = % s', [username])
        t = cur.fetchone()
        if not t:
            fetchdata="INVALID DATA, PLEASE TRY AGAIN...."
            return render_template('index.html',data=fetchdata)   
            
        dob=str(t[0])  
        cur = mysql.connection.cursor()
        cur.execute('SELECT password FROM users WHERE username = % s', [username])
        account = cur.fetchone()
        cur.close()
        if account:
            password_from_db=str(account[0])
            password=ECC(username,password,dob)
            if(pbkdf2_sha256.verify(password,password_from_db)):
                #fetchdata="LOGGED IN SUCCESSFULLY...."
                return redirect('https://en.wikipedia.org/wiki/Elliptic-curve_cryptography')
            else:
                fetchdata="INVALID DATA, PLEASE TRY AGAIN...."
        else:   
            #fetchdata="INVALID DATA, PLEASE TRY AGAIN...."
            fetchdata=username+password+dob
    return render_template('index.html',data=fetchdata)
    
@app.route('/register_status',methods=['POST'])
def predict_status():
    username=request.form['username']
    password=request.form['password']
    cpassword=request.form['cpassword']
    dob=request.form['dob']
    if(username=="" or password=="" or cpassword=="" or dob==""):
        fetchdata="PLEASE FILL ALL THE DETAILS...."
        return render_template('register.html',data=fetchdata)
    elif(len(password)<6):
        fetchdata="PASSWORD SHOULD HAVE ATLEAST 6 CHARACTERS"
        return render_template('register.html',data=fetchdata)
    elif(password!=cpassword):
        fetchdata="PASSWORDS DO NOT MATCH, PLEASE TRY AGAIN...."
        return render_template('register.html',data=fetchdata)
    elif(dob[2]!='/' or dob[5]!='/'):
        fetchdata="Please enter date in dd/mm/yyyy format"
        return render_template('register.html',data=fetchdata)
    else:
        username=request.form['username']
        password=request.form['password']
        cpassword=request.form['cpassword']
        dob=request.form['dob']
        
        password=ECC(username,password,dob)
        password=hash_password(password)
        
        cur = mysql.connection.cursor()
        cur.execute('SELECT * FROM users WHERE username = % s', [username])
        account = cur.fetchone()
        if account:
            fetchdata="USER ALREADY EXISTS.."
            return render_template('register.html',data=fetchdata)
        cur.execute("""INSERT INTO users (username,password,dob) VALUES(%s,%s,%s)""",(username,password,dob))
        mysql.connection.commit()
        cur.close()
        fetchdata="REGISTERED SUCCESSFULLY...."
    return render_template('register.html',data=fetchdata)
    


if __name__ == "__main__":
	app.run(debug=True)