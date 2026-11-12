from config import Config,emailTemplates
import mysql.connector as sql
import random
import smtplib
from email.message import EmailMessage
from flask import Flask, render_template, request, session, redirect,url_for,flash
import bcrypt
from werkzeug.utils import secure_filename
import os
import sys

#create an upload folder if not exists
if not os.path.exists('upload'):
    os.mkdir('upload')      #it will create a floder

#Setting up a secure way to generate and verify timed tokens in Flask App
from itsdangerous import URLSafeTimedSerializer,BadSignature,TimedSerializer

app = Flask(__name__)
app.secret_key = "lavanya@123"

DBconfig = Config()
from_email = DBconfig.from_email
email_app_password = DBconfig.email_app_password

# 1. Generate Password Hash
def generateHash(text):
    btext = text.encode('utf-8')
    cipher_text = bcrypt.hashpw(btext, bcrypt.gensalt(12))
    return cipher_text.decode('utf-8')

# 2. Database Connection
def getConnectionWithDB():
    try:
        connection = sql.connect(
            host=DBconfig.db_host,
            port=DBconfig.db_port,
            user=DBconfig.db_user,
            password=DBconfig.db_password,
            database=DBconfig.db_name
        )
        return connection
    except sql.Error as e:
        print("Database Connection Error:", e)
        return None

# 3. Insert User Record
def insertUserRecord(user_data):
    connection = getConnectionWithDB()
    if connection is None:
        return False
    cursor = None
    try:
        cursor = connection.cursor()
        query = """
        INSERT INTO users(name, email, password_hash) VALUES(%s, %s, %s)"""
        values = (
            user_data['name'],
            user_data['email'],
            user_data['password_hash']
        )
        cursor.execute(query, values)
        connection.commit()
        return True
    except sql.Error as e:
        print("Insert Error:", e)
        connection.rollback()
        return False
    finally:
        if cursor:
            cursor.close()
        connection.close()
# 4. Read All User Records
def readUserRecords():
    connection = getConnectionWithDB()
    if connection is None:
        return False
    cursor = None
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users")
        data = cursor.fetchall()
        records = []
        for record in data:
            temp = {
                'ID': record[0],
                'name': record[1],
                'email': record[2],
                'PASSWORD_HASH': record[3],
                'IS_VERIFIED': record[4],
                'CREATED_AT': record[5]
            }
            records.append(temp)
        return records
    except sql.Error as e:
        print("Read Error:", e)
        return False
    finally:
        if cursor:
            cursor.close()
        connection.close()

# 5. Read User Record By Email
def readUserRecordbyEmail(user_data):
    email = user_data['email']
    connection = getConnectionWithDB()
    if connection is None:
        return False
    cursor = None
    try:
        cursor = connection.cursor()
        query = """ SELECT id, name, email, password_hash, IS_VERIFIED FROM users WHERE email = %s"""
        cursor.execute(query, (email,))
        data = cursor.fetchone()
        if data is None:
            return "No Record"
        record = {
            'id': data[0],
            'name': data[1],
            'email': data[2],
            'password_hash': data[3],
            'IS_VERIFIED':data[4]
        }
        return record
    except sql.Error as e:
        print("Read Email Error:", e)
        return False

    finally:
        if cursor:
            cursor.close()
        connection.close()


# 6. Read User Record By ID
def readUserRecordbyId(user_data1):
    user_id = user_data1['id']

    connection = getConnectionWithDB()

    if connection is None:
        return False

    cursor = None

    try:
        cursor = connection.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE id = %s",
            (user_id,)
        )

        data = cursor.fetchone()

        if data is None:
            return "No Record"

        record = {
            'id': data[0],
            'name': data[1],
            'email': data[2],
            'password_hash': data[3]
        }

        return record

    except sql.Error as e:
        print("Read ID Error:", e)
        return False

    finally:
        if cursor:
            cursor.close()
        connection.close()


# 7. Update Name By ID Or Email
def updateNamebyIDorEmail(user_data):
    connection = getConnectionWithDB()

    if connection is None:
        return False

    cursor = None

    try:
        cursor = connection.cursor()

        new_name = user_data['new_name']

        if 'id' in user_data:
            query = "UPDATE users SET name = %s WHERE id = %s"
            values = (new_name, user_data['id'])
        else:
            query = "UPDATE users SET name = %s WHERE email = %s"
            values = (new_name, user_data['email'])

        cursor.execute(query, values)
        connection.commit()

        return cursor.rowcount > 0

    except sql.Error as e:
        print("Update Name Error:", e)
        connection.rollback()
        return False

    finally:
        if cursor:
            cursor.close()
        connection.close()


# 8. Update Password By ID Or Email
def updatepasswordByIdorEmail(user_data):
    connection = getConnectionWithDB()

    if connection is None:
        return False

    cursor = None

    try:
        cursor = connection.cursor()

        new_password = generateHash(user_data['new_password'])

        if 'id' in user_data:
            query = """
            UPDATE users SET password_hash = %s WHERE id = %s
            """
            values = (new_password, user_data['id'])
        else:
            query = """UPDATE users SET password_hash = %s WHERE email = %s """
            values = (new_password, user_data['email'])

        cursor.execute(query, values)
        connection.commit()
        return cursor.rowcount > 0
    except sql.Error as e:
        print("Update Password Error:", e)
        connection.rollback()
        return False
    finally:
        if cursor:
            cursor.close()
        connection.close()

# 9. Update Verified Status
def updateVerifiedByIdorEmail(user_data):
    connection = getConnectionWithDB()
    if connection is None:
        return False
    cursor = None
    try:
        cursor = connection.cursor()
        new_status = user_data['new_IS_VERIFIED']
        if 'id' in user_data:
            query = """UPDATE users SET IS_VERIFIED = %s WHERE id = %s"""
            values = (new_status, user_data['id'])
        else:
            query = """UPDATE users SET IS_VERIFIED = %s WHERE email = %s"""
            values = (new_status, user_data['email'])
        cursor.execute(query, values)
        connection.commit()
        return cursor.rowcount > 0
    except sql.Error as e:
        print("Update Verification Error:", e)
        connection.rollback()
        return False
    finally:
        if cursor:
            cursor.close()
        connection.close()

# 10. Generate OTP
def generateOTP():
    otp = random.randint(1000, 9999)
    return otp

# 11. Send OTP Through Email
def sendOTPviaemail(to_email, otp):
    try:
        message = EmailMessage()
        message['Subject'] = "OTP Notification"
        message['From'] = from_email
        message['To'] = to_email
        message.set_content(f"Your OTP is {otp}")
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(from_email, email_app_password)
            server.send_message(message)
        return True
    except Exception as e:
        print("Email Error:", e)
        return False

def sendEmail(subject:str,to_email:str,body:str):
    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = from_email
    message['To'] = to_email
    message.set_content(body)
    with smtplib.SMTP("smtp.gmail.com",587) as server:
        server.starttls()
        server.login(from_email,email_app_password)
        server.send_message(message)
    return True    

# 12. Validate User Data
def validateData(user_data):
    errors = []
    name = user_data['name']
    email = user_data['email']
    password = user_data['password']
    confirm_password = user_data['confirm_password']
    if len(name) < 2:
        errors.append("Invalid Name")
    if len(email) < 5 or '@' not in email:
        errors.append("Invalid Email")
    if len(password) < 6:
        errors.append("Password must contain at least 6 characters")
    if password != confirm_password:
        errors.append("Password Mismatch")
    return errors

# 13. Verify Duplicate Email
def verifyDuplicateEmail(user_data):
    record = readUserRecordbyEmail(user_data)
    if record == "No Record":
        return False
    elif record is False:
        return None
    else:
        return True

serializer = URLSafeTimedSerializer(app.secret_key)
def resetpasswordTokenGenerate(email):
    token = serializer.dumps(email,
                             salt="reset-password")
    return token

def validateToken(token):
    try:
        data = serializer.loads(token,
                                salt = "reset-password",
                                max_age = 300)
        return data
    except BadSignature:
        return "Invalid"
    except TimedSerializer:
        return "Timeout"

#-----------------------------
# Notes functions
# ----------------------------    

# Get all notes belonging to a particular user
def getNotesByUserId(user_id):
    try:
        connection = getConnectionWithDB()

        if connection is None:
            return False, "Database Connection Failed"

        cursor = connection.cursor(dictionary=True)

        get_notes_query = """
            SELECT ID AS id, USER_ID AS user_id,
                   TITLE AS title, CONTENT AS content
            FROM NOTES
            WHERE USER_ID = %s
        """

        cursor.execute(get_notes_query, (user_id,))
        notes = cursor.fetchall()

        cursor.close()
        connection.close()

        return True, notes

    except Exception as e:
        print("Get Notes Error:", e)
        return False, f"Exception raised in get Notes: {e}"

#insert notes records in table

# Insert notes records into table
def addNotesRecord(user_id: int, title: str, content: str):
    try:
        connection = getConnectionWithDB()

        if connection is None:
            return False, "Database Connection Failed"

        cursor = connection.cursor()

        add_notes_query = """
            INSERT INTO NOTES (USER_ID, TITLE, CONTENT)
            VALUES (%s, %s, %s)
        """

        cursor.execute(add_notes_query, (user_id, title, content))

        connection.commit()

        cursor.close()
        connection.close()

        return True, "Notes Saved Successfully"

    except Exception as e:
        print("Add Notes Error:", e)
        return False, f"Exception raised in add notes: {e}"


#get notes by id

# Get notes by ID
def getNotesById(notes_id):
    try:
        connection = getConnectionWithDB()

        if connection is None:
            return False, "Database Connection Failed"

        cursor = connection.cursor(dictionary=True)

        get_notes_query = """
            SELECT
                ID AS id,
                TITLE AS title,
                CONTENT AS content
            FROM NOTES
            WHERE ID = %s
        """

        cursor.execute(get_notes_query, (notes_id,))
        notes = cursor.fetchone()

        cursor.close()
        connection.close()

        if notes is None:
            return False, "Notes Not Found"

        return True, notes

    except Exception as e:
        print("View Notes Error:", e)
        return False, str(e)
      

#update notes by id
def updateNotesByID(notes_id:int,title:str,content:str):
    try:
        connection = getConnectionWithDB()
        if connection == "Connection Failed":
            return False,"Database Connection Failed"
        else:
            cursor = connection.cursor()
            update_notes_by_id = """UPDATE NOTES SET TITLE=%s,CONTENT=%s WHERE ID=%s"""
            cursor.execute(update_notes_by_id,(title,content,notes_id))
            connection.commit()
            cursor.close()
            connection.close()
            return True,"Notes Updated"
    except Exception as e:
        return False,f"Exception raised in updated notes: {e}"
    
#delete notes by id
def deleteNotesById(notes_id, user_id):

    try:
        query = "DELETE FROM notes WHERE id = %s AND user_id = %s"

        cursor.execute(query, (notes_id, user_id))
        mysql.connection.commit()

        if cursor.rowcount > 0:
            return True, "Note deleted successfully"
        else:
            return False, "Note not found"

    except Exception as e:
        return False, str(e)   

#----------------------
# File methods
#----------------------

#check file exist in allowed types
def checkFileAllowed(filename):
    allowed_types = ['pdf','doc','jpeg','jpg','svg','csv','xml','txt']
    if "." in filename and filename.split('.')[1] in allowed_types:
        return True
    else:
        return False

#check duplicate file
def checkFileDuplicate(userid,filename):
    try:
        connection=getConnectionWithDB()
        if connection=="Connection Failed":
            return False,"Database Connection Failed"
        else:
            cursor=connection.cursor()
            check_file_duplicate="""select*from file_data
            where stored_name=%s and user_id=%s;"""
            cursor.execute(check_file_duplicate,(filename,userid))
            record=cursor.fetchone()
            cursor.close()
            connection.close()
            if record:
                return False,"Duplicate filr is present"
            else:
                return True,"Not a Duplicate file"
    except Exception as e:
        return False,f"Exception raised in file:{e}"

#insert files into table
def uploadFileInDB(userid,filename,stored_name,type,size,path):
    try:
        connection = getConnectionWithDB()
        if connection == "Connection Failed":
            return False,"Database Connection Failed"
        else:
            cursor = connection.cursor()
            insert_filedata_query = """insert into file_data(USER_ID,ORIGINAL_NAME,STORED_ NAME,
            MIME_TYPE,SIZE_BYTES,STORAGE_PATH) values(%s,%s,%s,%s,%s,%s);"""
            cursor.execute(insert_filedata_query,(userid,filename,stored_name,type,size,path))
            connection.commit()
            cursor.close()
            connection.close()
            return True,"File Uploaded"
    except Exception as e:
        return False,f'Exception raised in file upload:{e}'    

#get file metadata by file_id
def getFileByFileId(fileid):
    try:
        connection = getConnectionWithDB()
        if connection == "Connection Failed":
            return False,"Database Connection Failed"
        else:
            cursor = connection.cursor(dictionary=True)
            get_file_by_user_id = """select * from file_data where id = %s;"""
            cursor.execute(get_file_by_user_id,((fileid,))) 
            file=cursor.fetchone()
            cursor.close()
            connection.close()
            return True,file
    except Exception as e:
        return False,f'Exception raised in View diles:{e}'  


# ROUTES

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == "GET":
        return render_template('login.html')
    elif request.method == "POST":
        email = request.form['email']
        password= request.form['password']
        #we have to check account existed or not
        user_data = {'email':email}
        record = readUserRecordbyEmail(user_data=user_data)
        print("Login Data:",record)
        if record:
            #if data exists
            if record['IS_VERIFIED'] == True:
                login_status = bcrypt.checkpw(password.encode('utf-8'),
                                              record['password_hash'].encode('utf-8')
                                              )
                print(login_status)
                if login_status:
                    #create a session,inside that we need to store email
                    session['email'] = email
                    session['id'] = record['id']
                    session['name'] = record['name']
                    return redirect('/dashboard')
                else:
                    return redirect('/login')
            else:
                return redirect('/login')
        else:
            return redirect('/login') 

@app.route('/register',methods=['GET','POST'])
def register():
    global OTP
    if(request.method=="GET"):
        return render_template('register.html')
    elif(request.method=="POST"):
        name=request.form['name']
        email=request.form['email']
        password=request.form['password']
        confirm_password=request.form['confirm_password']
        user_data={
            'name':name,
            'email':email,
            'password':password,
            'confirm_password':confirm_password
        }
        errors = validateData(user_data)
        if len(errors)>0:
            return render_template('register.html',errors=errors)
        else:
            is_duplicate = verifyDuplicateEmail(user_data)
            if is_duplicate == False:
                #if there is no account
                #convert password to hash value
                session['otp'] = generateOTP()
                #OTP = generateOTP()
                password_hash = generateHash(user_data['password'])
                name = user_data['name']
                email = user_data['email']
                status = insertUserRecord({
                   'name':name,
                   'email':email,
                   'password_hash':password_hash
                })
                #status of insertion
                if status == True:
                   session['username'] = email
                   # Generate OTP
                   otp = random.randint(100000, 999999)

                  # Store OTP in session
                   session['otp'] = otp
                   #sendOTPviaemail(email,otp)
                   sendEmail(subject="Verify Your Registration - Notes Management",to_email=email,
                             body=emailTemplates.send_otp_template(username=name,otp=otp))
                   return redirect('/verify')
                #    return render_template('register.html',
                #                           res="Registration Succesfully Completed")
                else:
                   return render_template('register.html',
                                          err="Registration Failed")
                              
            else:
                return render_template('register.html',
                                       err="Account already existed")

#forgot_password route
@app.route("/forgot_password",methods=['GET','POST'])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")
    if request.method == "POST":
        email = request.form.get("email",None)
        #check whether the email exits in db or not
        data = {'email':email}
        record = readUserRecordbyEmail(user_data=data)
        if 'id' in record:
            #send mail generation of token
            token = resetpasswordTokenGenerate(
                email=email)
            #reset password url
            reset_url = url_for('reset_password',
                                token=token,
                                _external = True)
            email_status = sendEmail(
                subject = "Reset Password -  SNS",
                to_email = email,
                body = emailTemplates.send_reset_password_template(
                    user_name=record['name'],
                    url=reset_url,
                    time=5
                ))
            if email_status:
                return render_template("forgot_password.html",
                                       msg="Email has been sent")
            else:
                return render_template("forgot_password.html",
                                       error="Unable to send email")
        else:
            return render_template("forgot_password.html",
                                   error="enter a valid email")    

#Reset Password
@app.route('/reset_password/<string:token>',
           methods=['GET','POST'])
def reset_password(token):
    token_status = validateToken(token)
    if token_status=="Invalid":
        return render_template('forgot_password.html',
                               error="Invalid URL")
    elif token_status=="Timeout":
        return render_template('forgot_password.html',
                               error="URL Expired")
    email = token_status
    if request.method == "GET":
        return render_template('reset_password.html',
                               token=token)
    #post request
    if request.method == "POST":
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password == confirm_password:
            # updatepasswordByIdorEmail hashes the password before saving it
            password_hash = generateHash(text = new_password)
            data = {'email': email, 'new_password': password_hash}
            if updatepasswordByIdorEmail(data):
                return redirect('/login')
            else:
                return render_template('reset_password.html')

        return render_template('reset_password.html',
                               error="Passwords do not match")


@app.route('/dashboard')
def dashboard():
    #if the user data is not in thesession redirect to login page
    if "id" not in session:
        return redirect("/login")
    return render_template("dashboard.html",
                           user_name=session['name'])

@app.route('/user/profile',methods=['GET'])
def profile():
    if "id" not in session:
        redirect('/login')
    name = session['name']
    email = session['email']
    return render_template("profile.html",email=email,
                           name=name)


@app.route('/verify',methods = ['GET','POST'])
def verify():
   if request.method == "GET":
      return render_template('verify.html')
   elif request.method == "POST":
      try:
          otp = int(request.form['otp'])
      except (KeyError, ValueError):
          return render_template('verify.html', err="Invalid OTP")

      if otp == session.get('otp'):
          is_verify = True
          email = session.get('username')
          updateVerifiedByIdorEmail({'email': email, 'new_IS_VERIFIED': is_verify})
          return redirect('/login')
      else:
          return render_template('verify.html',err="Invalid OTP")

#---------------------
#Notes routes
#----------------------

@app.route('/notes',methods=['GET','POST'])
def mynotes():
    if "id" not in session:
        return redirect('/login')
    if request.method == "GET":
        #get user notes from the data
        id = session['id']
        print(id)
        status,notes = getNotesByUserId(user_id=id)
        print(notes)
        if status == True:
            return render_template("notes.html",
                                   notes = notes)
        else:
            return render_template('notes.html',err=notes)

#add notes route
@app.route('/notes/addnotes',methods=['GET','POST'])
def add_notes():
    if "id" not in session:
        return redirect('/login')
    #GET request
    if request.method == "GET":
        return render_template('addnotes.html')
    #POST request
    if request.method == "POST":
        title = request.form.get('Title',"No Title")
        content = request.form.get('content',"No Content")
        #store in database
        status,msg = addNotesRecord(
            user_id = session['id'],
            title = title,
            content = content
        )
        if status == True:
            #redirect to notes dashboard
            return render_template('notes.html',msg=msg)
        else:
            return render_template('notes.html',err=msg)

#view notes route

# View notes route
@app.route('/notes/view/<int:note_id>')
def view_notes(note_id):

    if "id" not in session:
        return redirect('/login')

    status, notes = getNotesById(notes_id=note_id)

    if status:
        title = notes['title']
        content = notes['content']

        return render_template(
            'viewnotes.html',
            title=title,
            content=content
        )

    else:
        return render_template('notes.html', err=notes)


#edit notes route
@app.route('/notes/edit/<int:note_id>',methods=['GET','POST'])
def edit_notes(note_id):
    #get notes from the database 
    if request.method == "GET":
        status,notes = getNotesById(notes_id=note_id)
        if status == True:
            return render_template('updatenotes.html',
                                   title=notes['title'],
                                   content = notes['content'],
                                   notes_id=note_id)
        else:
            return render_template('notes.html',err=notes)
    #Post Request
    if request.method == "POST":
        title = request.form.get('title')
        content = request.form.get('content')
        print(title,content)
        #update notes contnet in database as per notes id
        status,msg = updateNotesByID(
            title = title,content=content,notes_id=note_id)
        _,notes = getNotesByUserId(session['id'])
        if status == True:
            return render_template('notes.html',msg=msg,notes=notes)
        else:
            return render_template('notes.html',err=msg,notes=notes)
            

# Delete notes route
@app.route('/notes/delete/<int:note_id>', methods=['GET'])
def delete_notes(note_id):

    if "id" not in session:
        return redirect('/login')

    user_id = session['id']

    status, msg = deleteNotesById(
        notes_id=note_id,
        user_id=user_id
    )

    _, notes = getNotesByUserId(user_id=user_id)

    if status:
        return render_template(
            'notes.html',
            msg=msg,
            notes=notes
        )
    else:
        return render_template(
            'notes.html',
            err=msg,
            notes=notes
        )

#--------------------------------
#     Files Route
#--------------------------------

@app.route('/files')         #here we have default method GET
def myfiles():
    if "id" not in session:
        return redirect('/login')
    if request.method =="GET":
        return render_template('files.html')

#upload file route
@app.route('/files/upload',methods=['GET','POST'])
def uploadFile():
    if "id" not in session:
        return redirect('/login')
    #GET request
    if request.method == "GET":
        return render_template('uploadFile.html')
    #POST request
    if request.method == 'POST':
        #get file from form
        file = request.form.get('file')
        if file and file.filename != "":
            #check file in allowed types
            filename = file.filename
            if checkFileAllowed(filename=filename):
                #check the valid allowed types of files
                filename_secure = secure_filename(filename)
                #check the file in allowed types
                status,msg = checkFileDuplicate(
                    userid=session['id'],
                    filename=filename_secure
                )
                if status == True:
                    #save the file
                    upload_path = os.path.join('upload',filename_secure)
                    file.save(upload_path)
                    #get the file infomation
                    file_size = os.path.getsize(upload_path)
                    file_type = os.path.splitext(filename_secure)[1].lower().lstrip('.')
                    #path stored in the DB
                    filepath = f'/upload/{filename_secure}'
                    #insert file metadata in database
                    status,msg = uploadFileInDB(userid=session['id'],
                                                filename=filename,
                                                stored_name=filename_secure,
                                                type=file_type,
                                                size=file_size,
                                                path=filepath)
                    if status == True:
                        flash(msg,"msg")       #diplay tempory msg it is  a finction in flask
                        return redirect('/files')
                    else:
                        flash(msg,"err")
                        return redirect('/files')
                else:
                    flash(msg,"err")
                    return redirect('/files')  
            else:
                flash("File type not allowed","err")
                return redirect('/files')
            #render_template -->returns HTML directly to currentuRL
            #redirect --> instructs the brower to make a new request to a different URL
        else:
            flash("File not uploaded","err")
            return redirect('/files')          





#view file route
@app.route('/files/view/<file_id>')
def viewfile():
    if "id" not in session:
        return redirect('/login')
    pass

#download file route
@app.route('/files/download/<file_id>')
def downloadFile():
    if "id" not in session:
        return redirect('/login')
    pass

#delete file route
@app.route('/files/delete/<file_id>')
def deleteFile():
    if "id" not in session:
        return redirect('/login') 
    pass



#logout route
@app.route("/logout",methods=['GET'])
def logout():
    #if id in session 
    session.pop('id',None)
    session.pop('name',None)
    session.pop('email',None)
    return redirect('/login')


if __name__=="__main__":
    app.run(host='0.0.0.0', 
            port = 5000,
            debug=True)
    




#Registration Flow:

#User-->register.html-->Registration form-->Post-->Python-->collecting Data-->Validating-->Verifying-->Password to password hash-->MySQL Table

#HTML <-> Python <-> MySQL

#Registration Flow
#User has to click on get Started
#Register page
#Name,email,password,confrim password and submit
#verifyDuplicateEmail() --> if account not exits
#generate OTP
#send email with otp
#redirect to verify.html
#enter the otp received on email
#if the otp matches with the session otp
#it will redirect to login
#if they are not matching,it redirects with a message




# @app.route('/register',methods = ['GET','POST'])
# def register():
#    if request.method == "GET":
#       renderHTMLPage()
#     elif request.method == "POST":
#       collectUserData()
#       validateUserData()
#       displayErrors()
#       status = verifyAccountExist()
#       if status:
#          insertRecord()
#       else:
#          displayErrorMessage()
