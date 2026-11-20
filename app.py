from config import Config,emailTemplates
import mysql.connector as sql
import random
import smtplib
from email.message import EmailMessage
from flask import Flask,render_template,redirect,url_for,request,session,flash,send_file
import bcrypt
from werkzeug.utils import secure_filename
import os
import sys
import mimetypes

#create an upload folder if not exists
if not os.path.exists('upload'):
    os.mkdir('upload') #it will create a folder..
#Setting up a secure way to generate and verify timed
#tokens in Flask app
from itsdangerous import URLSafeTimedSerializer,BadSignature,TimedSerializer
app = Flask(__name__)
app.secret_key = "Codegnan@123"

DBConfig = Config()
from_email = DBConfig.from_email
email_app_password = DBConfig.email_app_password
#Encode -->Str to Bytes
#Decode --> Bytes to Str
#gensalt --> is it used to generate a key
#how many rounds this key to iterate
#gensalt(4)
def generateHash(text):
    btext=text.encode('utf-8')
    cipher_text = bcrypt.hashpw(btext,bcrypt.gensalt(4))
    return cipher_text.decode('utf-8')
    #print(cipher_text,len(cipher_text))
    #print(text[0],btext[0]) #returns encoded value
    #print(type(btext))
    #bcrypt.hashpw(btext)
#generateHash("Saketh")
#We will first make connection with DB
def getConnectionWithDB():
    db_host = DBConfig.db_host
    db_port = DBConfig.db_port
    db_user = DBConfig.db_user
    db_password = DBConfig.db_password
    db_name = DBConfig.db_name
    #print(db_name,db_host)
    try:
        connection = sql.connect(
            host=db_host,
            port = db_port,
            user = db_user,
            password = db_password,
            database = db_name
        )
        return connection
    except:
        return "Connection Failed"
#Insert the data into the table
def insertUserRecord(user_data):
    """Inserting User records"""
    name = user_data['name']
    email = user_data['email']
    password_hash = user_data['password_hash']
    connection = getConnectionWithDB()
    if connection == "Connection Failed":
        return False
    else:
        try:
            cursor = connection.cursor()
            cursor.execute(
            "INSERT INTO users(name,email,password_hash) values(%s,%s,%s)",(name,email,password_hash))
            connection.commit()
            cursor.close()
            connection.close()
            return True
        except:
            print("Data cannot be inserted")
            return False
#Now let us  define the data
data = [
    {
        'name': 'Shekar',
        'email': 'shekar1505@gmail.com',
        'password_hash': '1a2b3c4d'
    },
    {
        'name': 'Mamatha',
        'email': 'mamtha0803@gmail.com',
        'password_hash': '5e6f7g8h'
    },
    {
        'name': 'Sai',
        'email': 'Sai@codegnan.com',
        'password_hash': '9i0j1k2l'
    }
]
#for user in data:
# #    result = insertUserRecord(user)

#Let us create multiple functions to access the data from
#the tables,along with specific user wise (id,name,email)

def readUserRecords():
    connection = getConnectionWithDB()
    if connection == "Connection Failed":
        return False
    else:
        cursor = connection.cursor()
        cursor.execute("SELECT * from users")
        data = cursor.fetchall()
        records = []
        for record in data:
            temp = {}
            #print(record)
            temp['id'] = record[0]
            temp['name'] = record[1]
            temp['email'] = record[2]
            temp['password_hash'] = record[3]
            temp['is_verified'] = record[4]
            temp['created_at'] = record[5]
            records.append(temp)
        cursor.close()
        connection.close()
        return records
#print(readUserRecords())
def readUserRecordbyEmail(user_data):
    email = user_data['email']
    connection = getConnectionWithDB()
    if connection == "Connection Failed":
        return False
    else:
        try:
            cursor = connection.cursor()
            cursor.execute("SELECT * from users where email=%s",
                       (email,))
            data = cursor.fetchone()
        #print(data)
            record = {
                "id":data[0],
                "name":data[1],
                "email":data[2],
                "password_hash":data[3],
                "is_verified":data[4],
                "created_at":data[5]}
            return record
        except:
             cursor.close()
             connection.close()
             return "No Record"
def readUserRecordbyId(user_data):
    id=user_data['id']
    connection=getConnectionWithDB()
    if connection=='Connection Failed':
        return False
    else:
        cursor=connection.cursor()
        cursor.execute("SELECT * from users where id=%s",(id,))
        data=cursor.fetchone()
        try:
            record={
                'id':data[0],
                'name':data[1],
                'email':data[2],
                'password_hash':data[3],
                'is_verified':data[4],
                'created_at':data[5]
            }
            cursor.close()
            connection.close()
            return record
        except:
            cursor.close()
            connection.close()
            return 'No record'

def updateNamebyIDorEmail(user_data):
    query_filter = ""
    try:
        id = user_data['id']
        query_filter = 'id'
    except:
        email = user_data['email']
        query_filter = "email"
    new_name = user_data['new_name']
    connection = getConnectionWithDB()
    if connection == "Connection Failed":
        return False
    else:
        cursor = connection.cursor()
        if query_filter == "id":
            query = "UPDATE users SET name = %s WHERE id = %s"
            values = (new_name,id)
        elif query_filter == "email":
            query = "UPDATE users SET name = %s WHERE email =%s"
            values = (new_name,email)
        cursor.execute(query,values)
        connection.commit()
        cursor.close()
        connection.close()
        return True
def updatePasswordByIdorEmail(user_data):
    query_filter = ""
    try:
        id = user_data['id']
        query_filter='id'
    except:
        email=user_data['email']
        query_filter='email'
    new_password = user_data['new_password']
    connection = getConnectionWithDB()
    if connection == "Connection Failed":
        return False
    else:
        cursor = connection.cursor()
        if query_filter == "id":
            query = "UPDATE users SET password_hash=%s WHERE id=%s"
            values = (new_password,id)
        elif query_filter == "email":
            query = "UPDATE users SET password_hash=%s WHERE email =%s"
            values = (new_password,email)
        cursor.execute(query,values)
        connection.commit()
        cursor.close()
        connection.close()
        return True
def updateVerifiedByIdorEmail(user_data):
    query_filter = ""
    try:
        id = user_data['id']
        query_filter='id'
    except:
        email=user_data['email']
        query_filter='email'
    verified = user_data['verified']
    connection = getConnectionWithDB()
    if connection == "Connection Failed":
        return False
    else:
        cursor = connection.cursor()
        if query_filter == "id":
            query = "UPDATE users SET is_verified=%s WHERE id=%s"
            values = (verified,id)
        elif query_filter == "email":
            query = "UPDATE users SET is_verified=%s WHERE email =%s"
            values = (verified,email)
        cursor.execute(query,values)
        connection.commit()
        cursor.close()
        connection.close()
        return True
def generateOTP():
    otp = random.randint(1000,9999)
    return otp
def sendOTPviaemail(to_email,otp):
    message = EmailMessage()
    message['Subject'] = "OTP Notification"
    message['From'] = from_email
    message['To'] = to_email
    message.set_content(
        f"Your OTP is {otp}"
    )
    with smtplib.SMTP("smtp.gmail.com",587) as server:
        server.starttls()
        server.login(from_email,email_app_password)
        server.send_message(message)
    return True
#sendOTPviaemail('sakethreddy.kallepu@gmail.com',5423)
def SendEmail(subject:str,to_email:str,body:str):
    message = EmailMessage()
    message['Subject'] = subject
    message['From']=from_email
    message['To'] = to_email
    message.set_content(body)
    with smtplib.SMTP("smtp.gmail.com",587) as server:
        server.starttls()
        server.login(from_email,email_app_password)
        server.send_message(message)
    return True









def validateData(user_data):
    errors =[]
    name=user_data['name']
    email=user_data['email']
    password = user_data['password']
    confirm_password = user_data['confirm_password']
    if name is None or len(name)<2:
        errors.append("Invalid Name")
    if email is None or len(email)<5:
        errors.append("Invalid Email")
    if password is None or len(password)<5:
        errors.append("Invalid Password")
    if password!=confirm_password:
        errors.append("Password mismatch")
    return errors
def verifyDuplicateEmail(user_data):
    #email = user_data['email']
    record = readUserRecordbyEmail(user_data)
    if (record=="No Record"):
        return False  #duplicate ledu
    else:
        return True  #duplicate undi

user_data = {'id':2,
             'name':"",
             'email':'shekar1505@gmail.com',
             'password':"12345",
             'confirm_password':'123',
             'new_password':'admin1234',
             'verified':True}
#print(validateData(user_data))
#print(updateNamebyIDorEmail(user_data))
#print(updateVerifiedByIdorEmail(user_data))
#print(generateOTP())
serializer = URLSafeTimedSerializer(app.secret_key)
def resetPasswordTokenGenerate(email):
    token = serializer.dumps(
        email,
        salt="reset-password"
    )
    return token
def validateToken(token):
    try:
        data = serializer.loads(
            token,
            salt="reset-password",
            max_age = 300
        )
        return data
    except BadSignature:
        return "Invalid"
    except TimedSerializer: #if token timeout
        return "Timeout"





@app.route('/')
def home():
    return render_template('index.html')
@app.route('/register',methods=['GET','POST'])
def register():
    if (request.method =="GET"):
        return render_template('register.html')
    elif (request.method=="POST"):
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password  = request.form['confirm_password']
        user_data = {
            "name":name,
            "email":email,
            "password":password,
            "confirm_password":confirm_password
        }
        errors = validateData(user_data)
        if len(errors)>0:
            return render_template('register.html',
                               errors=errors)
        else:
            is_duplicate = verifyDuplicateEmail(user_data)
            if is_duplicate == False: #duplicate ledu
                #if there is no account 
                #convert password to hash value
                OTP = generateOTP()
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
                    session['otp'] = OTP
                    #sendOTPviaemail(email,OTP)
                    SendEmail(subject="Verify Your Registration - Notes Management",
                              to_email=email,
                              body=emailTemplates.send_otp_template(username=name,
                                                                    otp=OTP))
                    return redirect('/verify')
                    #return render_template('register.html',
                                  #res="Registration Successfully Completed"
                                  #)
                else:
                    return render_template('register.html',
                                           err="Registration Failed")
            else: #duplicate undi
                return render_template('register.html',
                                       err="Account already exists")
#forgot password route
@app.route("/forgot_password",methods=['GET','POST'])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")
    if request.method == "POST":
        email = request.form.get("email",None)
        #check whether the email exists in db or not
        data = {'email':email}
        record = readUserRecordbyEmail(user_data=data)
        if 'id' in record:
            #send mail generation of token
            token = resetPasswordTokenGenerate(
                email=email)
            #reset password url
            reset_url = url_for('reset_password',
                                token=token,
                                _external=True)
            email_status = SendEmail(
                subject = "Reset Password - SNS",
                to_email=email,
                body = emailTemplates.send_reset_password_template(
                    username=record['name'],
                    url=reset_url,
                    time=5
                ))
            if email_status:
                return render_template("forgot_password.html",
                                       msg="Email has been sent")
            else:
                return render_template("forgot_password.html",
                                       error = "Unable to send email")
        else:
            return render_template("forgot_password.html",
                                   error="Enter a Valid email")
#reset-password route
@app.route('/reset-password/<string:token>',
           methods=['GET','POST'])
def reset_password(token):
    token_status= validateToken(token=token)
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
    #POST request
    if request.method == "POST":
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password'
                                            )
        if new_password == confirm_password:
            #generate hash password
            password_hash = generateHash(text = new_password)
            #update the password in the database
            data = {'email':email,
                    'new_password':password_hash}
            update = updatePasswordByIdorEmail(user_data=data)
            if update:
                #redirect to login page
                return redirect('/login')
            else:
                return render_template('reset_password.html')
        else:
            return render_template('reset_password.html',
                                   error="Password mismatch")
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
            if record['is_verified'] == True:
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

#total notes count
#total files count
def getFilesAndNotesCount(user_id):
    try:
        connection = getConnectionWithDB()
        if connection == "Connection Failed":
            return False,"Database Connection Failed"
        else:
            cursor = connection.cursor()
            get_notes_count = """SELECT COUNT(*) FROM NOTES 
                             WHERE USER_ID = %s;"""
            cursor.execute(get_notes_count,(user_id,))
            notes_count=cursor.fetchone()[0]
            get_files_count="""select count(*) from file_data
                            where user_id=%s;"""
            cursor.execute(get_files_count,(user_id,))
            files_count = cursor.fetchone()[0]
            cursor.close()
            connection.close()
            return notes_count,files_count
    except Exception as e:
        return False,f'Exception raised in count:{e}'

def recentNotes(user_id):
    try:
        connection = getConnectionWithDB()
        if connection == "Connection Failed":
            return False,"Database Connection Failed"
        else:
            cursor= connection.cursor(dictionary=True)
            get_recent_notes = """SELECT * FROM NOTES
                              WHERE USER_ID=%s ORDER BY updated_at
                              DESC LIMIT 3;"""
            cursor.execute(get_recent_notes,(user_id,))
            recent_notes = cursor.fetchall()
            cursor.close()
            connection.close()
            return True,recent_notes
    except Exception as e:
        return False,f"Exception raised in recent notes:{e}"
    
@app.route('/dashboard')
def dashboard():
    #if the user data is not in the session redirect to login page
    if "id" not in session:
        return redirect("/login")
    userid = session['id']
    notes_count,files_count = getFilesAndNotesCount(userid)
    _,recent_notes = recentNotes(userid)
    print(recent_notes)
    return render_template('dashboard.html',
                           username=session['name'],
                           total_notes = notes_count,
                           total_files=files_count,
                           notes=recent_notes)
#profile route
@app.route('/user/profile',methods=['GET'])
def profile():
    if "id" not in session:
        redirect('/login')
    name = session['name']
    email = session['email']
    return render_template("profile.html",
                           email=email,
                           name=name)
@app.route('/verify',methods = ['GET','POST'])
def verify():
    if request.method == "GET":
        return render_template('verify.html')
    elif request.method == "POST":
        otp = request.form['otp']
        otp = int(otp)
        if otp == session['otp']:
            is_verify = True
            updateVerifiedByIdorEmail(
                {'email':session['username'],'verified':is_verify})
            return redirect('/login')
        else:
            return render_template('verify.html',err="Invalid OTP")

#----------------------------
#       NOTES ROUTES
#----------------------------

# Get notes by logged-in user ID (with optional search)
def getNotesByUserId(user_id, filename=None):
    try:
        connection = getConnectionWithDB()

        if connection == "Connection Failed":
            return False, "Database Connection Failed"

        cursor = connection.cursor(dictionary=True)

        query = """
            SELECT id, user_id, title, content, created_at, updated_at
            FROM notes
            WHERE user_id = %s
        """
        values = [user_id]

        if filename:
            query += " AND title LIKE %s"
            values.append("%" + filename + "%")

        query += " ORDER BY updated_at DESC"

        cursor.execute(query, tuple(values))
        notes = cursor.fetchall()

        cursor.close()
        connection.close()

        return True, notes

    except Exception as e:
        return False, f"Exception in fetching notes: {e}"


# Get one note by note ID and user ID
def getNotesById(notes_id, user_id):
    try:
        connection = getConnectionWithDB()

        if connection == "Connection Failed":
            return False, "Database Connection Failed"

        cursor = connection.cursor(dictionary=True)

        query = """
            SELECT id, user_id, title, content, created_at, updated_at
            FROM notes
            WHERE id = %s AND user_id = %s
        """

        cursor.execute(query, (notes_id, user_id))
        note = cursor.fetchone()

        cursor.close()
        connection.close()

        if note:
            return True, note

        return False, "Note not found"

    except Exception as e:
        return False, f"Exception retrieving note: {e}"


# Notes list and search
@app.route('/notes', methods=['GET', 'POST'])
def mynotes():

    if "id" not in session:
        return redirect('/login')

    user_id = session['id']

    if request.method == "GET":

        status, notes = getNotesByUserId(user_id)

        if status:
            return render_template('notes.html', notes=notes)

        return render_template('notes.html', err=notes)

    # POST - search notes
    search_name = request.form.get('searchnotes', '').strip()

    status, notes = getNotesByUserId(
        user_id=user_id,
        filename=search_name
    )

    if status:
        return render_template('notes.html', notes=notes)

    return render_template('notes.html', err=notes)


# Insert notes into database
def addNotesRecord(user_id: int, title: str, content: str):
    try:
        connection = getConnectionWithDB()

        if connection == "Connection Failed":
            return False, "Database Connection Failed"

        cursor = connection.cursor()

        query = """
            INSERT INTO notes (user_id, title, content)
            VALUES (%s, %s, %s)
        """

        cursor.execute(query, (user_id, title, content))
        connection.commit()

        cursor.close()
        connection.close()

        return True, "Notes Saved Successfully"

    except Exception as e:
        return False, f"Exception in adding notes: {e}"


# Add notes route
@app.route('/notes/addnotes', methods=['GET', 'POST'])
def add_notes():

    if "id" not in session:
        return redirect('/login')

    if request.method == "GET":
        return render_template('addnotes.html')

    title = request.form.get('Title', '').strip()
    content = request.form.get('content', '').strip()

    if not title or not content:
        return render_template(
            'addnotes.html',
            err="Title and content are required"
        )

    status, msg = addNotesRecord(
        user_id=session['id'],
        title=title,
        content=content
    )

    if status:
        return redirect('/notes')

    return render_template('addnotes.html', err=msg)


# View notes
@app.route('/notes/view/<int:note_id>')
def view_notes(note_id):

    if "id" not in session:
        return redirect('/login')

    status, note = getNotesById(
        notes_id=note_id,
        user_id=session['id']
    )

    if status:
        return render_template(
            'viewnotes.html',
            notes=note,
            title=note['title'],
            content=note['content']
        )

    flash(note, "err")
    return redirect('/notes')


# Update notes by ID
def updateNotesByID(notes_id: int, user_id: int, title: str, content: str):
    try:
        connection = getConnectionWithDB()

        if connection == "Connection Failed":
            return False, "Database Connection Failed"

        cursor = connection.cursor()

        query = """
            UPDATE notes
            SET title = %s, content = %s
            WHERE id = %s AND user_id = %s
        """

        cursor.execute(query, (title, content, notes_id, user_id))
        connection.commit()

        if cursor.rowcount == 0:
            cursor.close()
            connection.close()
            return False, "Note not found"

        cursor.close()
        connection.close()

        return True, "Notes Updated Successfully"

    except Exception as e:
        return False, f"Exception updating notes: {e}"


# Edit notes
@app.route('/notes/edit/<int:note_id>', methods=['GET', 'POST'])
def edit_notes(note_id):

    if "id" not in session:
        return redirect('/login')

    user_id = session['id']

    # GET - fetch note for editing
    if request.method == "GET":

        status, note = getNotesById(
            notes_id=note_id,
            user_id=user_id
        )

        if status:
            return render_template(
                'updatenotes.html',
                title=note['title'],
                content=note['content'],
                notes_id=note['id']
            )

        flash(note, "err")
        return redirect('/notes')

    # POST - update note
    title = request.form.get('title', '').strip()
    content = request.form.get('content', '').strip()

    if not title or not content:
        status, note = getNotesById(note_id, user_id)

        if status:
            return render_template(
                'updatenotes.html',
                title=title,
                content=content,
                notes_id=note_id,
                err="Title and content are required"
            )

        return redirect('/notes')

    status, msg = updateNotesByID(
        notes_id=note_id,
        user_id=user_id,
        title=title,
        content=content
    )

    if status:
        flash(msg, "msg")
    else:
        flash(msg, "err")

    return redirect('/notes')


# Delete notes by ID
def deleteNotesById(notes_id, user_id):
    try:
        connection = getConnectionWithDB()

        if connection == "Connection Failed":
            return False, "Database Connection Failed"

        cursor = connection.cursor()

        query = """
            DELETE FROM notes
            WHERE id = %s AND user_id = %s
        """

        cursor.execute(query, (notes_id, user_id))
        connection.commit()

        if cursor.rowcount == 0:
            cursor.close()
            connection.close()
            return False, "Note not found"

        cursor.close()
        connection.close()

        return True, "Notes Deleted Successfully"

    except Exception as e:
        return False, f"Exception deleting notes: {e}"


# Delete notes route
@app.route('/notes/delete/<int:note_id>', methods=['GET', 'POST'])
def delete_notes(note_id):

    if "id" not in session:
        return redirect('/login')

    status, msg = deleteNotesById(
        notes_id=note_id,
        user_id=session['id']
    )

    if status:
        flash(msg, "msg")
    else:
        flash(msg, "err")

    return redirect('/notes')


# -----------------------------
# FILES SECTION
# -----------------------------

UPLOAD_FOLDER = os.path.abspath("upload")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Fetch files belonging to the logged-in user
def GetFilesbyUserId(userid, filename=None):
    try:
        connection = getConnectionWithDB()

        if connection == "Connection Failed":
            return False, "Database Connection Failed"

        cursor = connection.cursor(dictionary=True)

        query = """
            SELECT
                ID AS id,
                USER_ID AS user_id,
                ORIGINAL_NAME AS original_name,
                STORED_NAME AS stored_name,
                MIME_TYPE AS mime_type,
                SIZE_BYTES AS size_bytes,
                STORAGE_PATH AS storage_path
            FROM file_data
            WHERE USER_ID = %s
        """

        values = [userid]

        if filename:
            query += " AND ORIGINAL_NAME LIKE %s"
            values.append("%" + filename + "%")

        query += " ORDER BY ID DESC"

        cursor.execute(query, tuple(values))
        files = cursor.fetchall()

        cursor.close()
        connection.close()

        print("FILES DATA:", files)

        return True, files

    except Exception as e:
        return False, f"Exception in fetching files: {e}"


# Files page
@app.route('/files', methods=['GET', 'POST'])
def myfiles():

    if "id" not in session:
        return redirect('/login')

    if request.method == "GET":
        status, files = GetFilesbyUserId(session['id'])

    else:
        filename = request.form.get('searchfiles', '').strip()
        status, files = GetFilesbyUserId(
            session['id'],
            filename
        )

    if status:
        return render_template('files.html', files=files)

    flash(files, "err")
    return render_template('files.html', files=[])


# Check allowed file extensions
def checkFileAllowed(filename):
    allowed_extensions = {
        'pdf', 'doc', 'docx', 'jpeg', 'jpg', 'png',
        'svg', 'csv', 'xml', 'txt', 'py'
    }

    if '.' not in filename:
        return False

    extension = filename.rsplit('.', 1)[1].lower()
    return extension in allowed_extensions


# Check duplicate filename for a user
def checkFileDuplicate(userid, filename):
    try:
        connection = getConnectionWithDB()

        if connection == "Connection Failed":
            return False, "Database Connection Failed"

        cursor = connection.cursor()

        query = """
            SELECT id FROM file_data
            WHERE original_name = %s AND user_id = %s
        """

        cursor.execute(query, (filename, userid))
        record = cursor.fetchone()

        cursor.close()
        connection.close()

        if record:
            return False, "Duplicate file is present"

        return True, "Not a duplicate file"

    except Exception as e:
        return False, f"Exception checking duplicate: {e}"


# Insert file details into database
def UploadFileInDB(userid, filename, stored_name,
                   file_type, size, path):

    try:
        connection = getConnectionWithDB()

        if connection == "Connection Failed":
            return False, "Database Connection Failed"

        cursor = connection.cursor()

        query = """
            INSERT INTO file_data
            (user_id, original_name, stored_name,
             mime_type, size_bytes, storage_path)
            VALUES (%s, %s, %s, %s, %s, %s)
        """

        cursor.execute(query, (
            userid,
            filename,
            stored_name,
            file_type,
            size,
            path
        ))

        connection.commit()
        cursor.close()
        connection.close()

        return True, "File Uploaded Successfully"

    except Exception as e:
        return False, f"Exception in upload: {e}"


# Upload file
@app.route('/files/upload', methods=['GET', 'POST'])
def uploadFile():

    if "id" not in session:
        return redirect('/login')

    if request.method == "GET":
        return render_template('uploadFile.html')

    file = request.files.get('file')

    if not file or file.filename == "":
        flash("Please select a file", "err")
        return redirect('/files/upload')

    original_name = secure_filename(file.filename)

    if not checkFileAllowed(original_name):
        flash("File type not allowed", "err")
        return redirect('/files')

    status, msg = checkFileDuplicate(
        session['id'],
        original_name
    )

    if not status:
        flash(msg, "err")
        return redirect('/files')

    # Save using a unique filename
    import uuid

    extension = os.path.splitext(original_name)[1].lower()
    stored_name = f"{uuid.uuid4().hex}{extension}"

    upload_path = os.path.join(UPLOAD_FOLDER, stored_name)

    file.save(upload_path)

    file_size = os.path.getsize(upload_path)
    file_type = extension.lstrip('.')

    # Store relative file path in DB
    filepath = os.path.join("upload", stored_name)

    status, msg = UploadFileInDB(
        userid=session['id'],
        filename=original_name,
        stored_name=stored_name,
        file_type=file_type,
        size=file_size,
        path=filepath
    )

    if status:
        flash(msg, "msg")
    else:
        # Remove file if database insert fails
        if os.path.exists(upload_path):
            os.remove(upload_path)

        flash(msg, "err")

    return redirect('/files')


# Get file using file ID and user ID
def getFileByFileId(fileid, userid):

    try:
        connection = getConnectionWithDB()

        if connection == "Connection Failed":
            return False, "Database Connection Failed"

        cursor = connection.cursor(dictionary=True)

        query = """
            SELECT *
            FROM file_data
            WHERE id = %s AND user_id = %s
        """

        cursor.execute(query, (fileid, userid))
        file = cursor.fetchone()

        cursor.close()
        connection.close()

        if file:
            return True, file

        return False, "File not found"

    except Exception as e:
        return False, f"Exception retrieving file: {e}"


# Resolve file path
def getPhysicalFilePath(file):

    stored_name = file['STORED_NAME']

    path = os.path.abspath(
        os.path.join(UPLOAD_FOLDER, stored_name)
    )

    # Ensure the file is within upload directory
    if not path.startswith(UPLOAD_FOLDER + os.sep):
        return None

    return path


# View file
@app.route('/files/view/<int:file_id>', methods=['GET'])
def viewFile(file_id):

    if "id" not in session:
        return redirect('/login')

    status, file = getFileByFileId(
        fileid=file_id,
        userid=session['id']
    )

    if not status:
        flash(file, "err")
        return redirect('/files')

    path = getPhysicalFilePath(file)

    if not path or not os.path.isfile(path):
        flash("File does not exist on the server", "err")
        return redirect('/files')

    mime_type, _ = mimetypes.guess_type(path)

    return send_file(
        path,
        mimetype=mime_type,
        as_attachment=False
    )


# Download file
@app.route('/files/download/<int:file_id>', methods=['GET'])
def downloadFile(file_id):

    if "id" not in session:
        return redirect('/login')

    status, file = getFileByFileId(
        fileid=file_id,
        userid=session['id']
    )

    if not status:
        flash(file, "err")
        return redirect('/files')

    path = getPhysicalFilePath(file)

    if not path or not os.path.isfile(path):
        flash("File does not exist on the server", "err")
        return redirect('/files')

    return send_file(
        path,
        as_attachment=True,
        download_name=file['ORIGINAL_NAME']
    )


# Delete file
@app.route('/files/delete/<int:file_id>', methods=['POST'])
def deleteFile(file_id):

    if "id" not in session:
        return redirect('/login')

    status, file = getFileByFileId(
        fileid=file_id,
        userid=session['id']
    )

    if not status:
        flash(file, "err")
        return redirect('/files')

    path = getPhysicalFilePath(file)

    status, msg = deleteFileByFileId(
        fileid=file_id,
        userid=session['id']
    )

    if status:
        if path and os.path.isfile(path):
            os.remove(path)

        flash(msg, "msg")
    else:
        flash(msg, "err")

    return redirect('/files')


# Delete database record
def deleteFileByFileId(fileid, userid):

    try:
        connection = getConnectionWithDB()

        if connection == "Connection Failed":
            return False, "Database Connection Failed"

        cursor = connection.cursor()

        query = """
            DELETE FROM file_data
            WHERE id = %s AND user_id = %s
        """

        cursor.execute(query, (fileid, userid))
        connection.commit()

        deleted_count = cursor.rowcount

        cursor.close()
        connection.close()

        if deleted_count > 0:
            return True, "File Deleted Successfully"

        return False, "File not found"

    except Exception as e:
        return False, f"Exception deleting file: {e}"
#logout route
@app.route("/logout",methods=['GET'])
def logout():
    #if id in session
    session.pop('id',None)
    session.pop('name',None)
    session.pop('email',None)
    return redirect('/login')

if (__name__ == "__main__"):
    app.run(host="0.0.0.0",
            port = 5003,
            debug=True)
#Registration Flow:
#User --> register.html <--> Registration Form --> 
# POST <-->Python  -->Collecting Data -->Validating -> 
# Verifying -->Password to Password Hash <-->MYSQL Table

#HTML <-> Python <-> MYSQL

#Registration FLow
#User has to click on Get Started
#Register page
#Name,Email,Password,Confirm Password and submit
#verifyDuplicateEmail() --> if account not exists
#generate OTP
#send email with otp
#redirect to verify.html
#enter the otp receiveed on email
#if the otp matches with the session otp
#it will redirect to login
#if they are not matching,it redirects with a message




#@app.route('/register',methods = ['GET','POST'])
#def register():
#    if request.method == "GET":
#       renderHTMLPage()
#    elif request.method == "POST":
#        collectUserData()
#        validateUserData()
#        displayErrors()
#        status = verifyAccountExist()
#        if status:
#            insertRecord()
#        else:
#            displayErrorMessage()