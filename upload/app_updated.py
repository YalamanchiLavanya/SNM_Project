from config import Config,emailTemplates
import mysql.connector as sql
import random
import time
import smtplib
import mimetypes
from functools import wraps
from email.message import EmailMessage
from flask import (Flask,render_template,redirect,url_for,
                   request,session,flash,send_file)
import bcrypt
from werkzeug.utils import secure_filename
import os
#Setting up a secure way to generate and verify timed
#tokens in Flask app
from itsdangerous import (URLSafeTimedSerializer,BadSignature,
                          SignatureExpired)

app = Flask(__name__)
DBConfig = Config()
app.secret_key = DBConfig.secret_key
from_email = DBConfig.from_email
email_app_password = DBConfig.email_app_password

#create an upload folder if not exists
#(absolute path, so it works no matter where you start the app from)
UPLOAD_FOLDER = os.path.join(app.root_path,'upload')
os.makedirs(UPLOAD_FOLDER,exist_ok=True)

OTP_VALID_SECONDS = 180      # 3 minutes (matches the email text)
RESET_VALID_SECONDS = 300    # 5 minutes

#-------------------------------------------------
#   Helpers
#-------------------------------------------------
def login_required(view):
    """Redirect to /login when the user is not logged in."""
    @wraps(view)
    def wrapper(*args,**kwargs):
        if "id" not in session:
            return redirect(url_for('login'))
        return view(*args,**kwargs)
    return wrapper

#Encode -->Str to Bytes
#Decode --> Bytes to Str
def generateHash(text):
    btext=text.encode('utf-8')
    cipher_text = bcrypt.hashpw(btext,bcrypt.gensalt())
    return cipher_text.decode('utf-8')

#We will first make connection with DB
def getConnectionWithDB():
    try:
        connection = sql.connect(
            host=DBConfig.db_host,
            port = DBConfig.db_port,
            user = DBConfig.db_user,
            password = DBConfig.db_password,
            database = DBConfig.db_name
        )
        return connection
    except Exception as e:
        #print the real reason in the terminal so it can be debugged
        print("DB connection error:",e)
        return "Connection Failed"

#-------------------------------------------------
#   Users table
#-------------------------------------------------
def insertUserRecord(user_data):
    """Inserting User records"""
    connection = getConnectionWithDB()
    if connection == "Connection Failed":
        return False
    try:
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO users(name,email,password_hash) values(%s,%s,%s)",
            (user_data['name'],user_data['email'],
             user_data['password_hash']))
        connection.commit()
        cursor.close()
        connection.close()
        return True
    except Exception as e:
        print("Data cannot be inserted:",e)
        return False

def readUserRecordbyEmail(user_data):
    """Returns a dict, 'No Record', or False (DB down)"""
    connection = getConnectionWithDB()
    if connection == "Connection Failed":
        return False
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT * from users where email=%s",
                       (user_data['email'],))
        data = cursor.fetchone()
        cursor.close()
        connection.close()
        if data is None:
            return "No Record"
        return {
            "id":data[0],
            "name":data[1],
            "email":data[2],
            "password_hash":data[3],
            "is_verified":data[4],
            "created_at":data[5]}
    except Exception as e:
        print("readUserRecordbyEmail error:",e)
        return False

def _updateUser(column,value,user_data):
    """Update one column of a user, found by id or email."""
    connection = getConnectionWithDB()
    if connection == "Connection Failed":
        return False
    try:
        if 'id' in user_data:
            where,key = "id",user_data['id']
        else:
            where,key = "email",user_data['email']
        cursor = connection.cursor()
        cursor.execute(f"UPDATE users SET {column}=%s WHERE {where}=%s",
                       (value,key))
        connection.commit()
        cursor.close()
        connection.close()
        return True
    except Exception as e:
        print("Update user error:",e)
        return False

def updateNamebyIDorEmail(user_data):
    return _updateUser("name",user_data['new_name'],user_data)
def updatePasswordByIdorEmail(user_data):
    return _updateUser("password_hash",user_data['new_password'],user_data)
def updateVerifiedByIdorEmail(user_data):
    return _updateUser("is_verified",user_data['verified'],user_data)

#-------------------------------------------------
#   OTP / email
#-------------------------------------------------
def generateOTP():
    return random.randint(1000,9999)

def SendEmail(subject:str,to_email:str,body:str):
    """Returns True if the mail was sent, False otherwise."""
    try:
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
    except Exception as e:
        print("Email error:",e)
        return False

def validateData(user_data):
    errors =[]
    name=user_data['name']
    email=user_data['email']
    password = user_data['password']
    confirm_password = user_data['confirm_password']
    if name is None or len(name.strip())<2:
        errors.append("Invalid Name")
    if email is None or len(email)<5:
        errors.append("Invalid Email")
    if password is None or len(password)<5:
        errors.append("Invalid Password (minimum 5 characters)")
    if password!=confirm_password:
        errors.append("Password mismatch")
    return errors

#-------------------------------------------------
#   Reset password tokens
#-------------------------------------------------
serializer = URLSafeTimedSerializer(app.secret_key)
def resetPasswordTokenGenerate(email):
    return serializer.dumps(email,salt="reset-password")

def validateToken(token):
    try:
        return serializer.loads(token,salt="reset-password",
                                max_age=RESET_VALID_SECONDS)
    except SignatureExpired:   #must come BEFORE BadSignature
        return "Timeout"       #(it is a subclass of BadSignature)
    except BadSignature:
        return "Invalid"

#-------------------------------------------------
#   Auth routes
#-------------------------------------------------
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == "GET":
        return render_template('register.html')
    #POST
    name = request.form.get('name','').strip()
    email = request.form.get('email','').strip().lower()
    password = request.form.get('password','')
    confirm_password = request.form.get('confirm_password','')
    user_data = {"name":name,"email":email,
                 "password":password,"confirm_password":confirm_password}
    errors = validateData(user_data)
    if errors:
        return render_template('register.html',errors=errors)

    record = readUserRecordbyEmail({'email':email})
    if record is False:
        return render_template('register.html',
                               err="Database connection failed")
    password_hash = generateHash(password)
    if record == "No Record":
        #new user
        if not insertUserRecord({'name':name,'email':email,
                                 'password_hash':password_hash}):
            return render_template('register.html',
                                   err="Registration Failed")
    elif record['is_verified']:
        return render_template('register.html',
                               err="Account already exists")
    else:
        #registered earlier but never verified -> let them try again
        updateNamebyIDorEmail({'email':email,'new_name':name})
        updatePasswordByIdorEmail({'email':email,
                                   'new_password':password_hash})
    OTP = generateOTP()
    session['username'] = email
    session['otp'] = OTP
    session['otp_time'] = time.time()
    sent = SendEmail(subject="Verify Your Registration - Notes Management",
                     to_email=email,
                     body=emailTemplates.send_otp_template(username=name,
                                                           otp=OTP))
    if not sent:
        return render_template('register.html',
                               err="Could not send the OTP email. "
                                   "Check FROM_EMAIL / EMAIL_APP_PASSWORD in .env")
    flash("OTP sent to your email","msg")
    return redirect(url_for('verify'))

@app.route('/verify',methods = ['GET','POST'])
def verify():
    if request.method == "GET":
        return render_template('verify.html')
    if 'otp' not in session:
        flash("Session expired. Please register again.","err")
        return redirect(url_for('register'))
    if time.time() - session.get('otp_time',0) > OTP_VALID_SECONDS:
        session.pop('otp',None)
        flash("OTP expired. Register again with the same email "
              "to get a new OTP.","err")
        return redirect(url_for('register'))
    otp = request.form.get('otp','').strip()
    if otp.isdigit() and int(otp) == session['otp']:
        updateVerifiedByIdorEmail(
            {'email':session['username'],'verified':True})
        session.pop('otp',None)
        flash("Account verified. Please login.","msg")
        return redirect(url_for('login'))
    return render_template('verify.html',err="Invalid OTP")

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == "GET":
        return render_template('login.html')
    email = request.form.get('email','').strip().lower()
    password= request.form.get('password','')
    record = readUserRecordbyEmail({'email':email})
    if record is False:
        flash("Database connection failed","err")
        return redirect(url_for('login'))
    if record == "No Record":
        flash("No account found with this email","err")
        return redirect(url_for('login'))
    if not record['is_verified']:
        flash("Account not verified. Register again with the same "
              "email to get a new OTP.","err")
        return redirect(url_for('login'))
    if bcrypt.checkpw(password.encode('utf-8'),
                      record['password_hash'].encode('utf-8')):
        session['email'] = record['email']
        session['id'] = record['id']
        session['name'] = record['name']
        return redirect(url_for('dashboard'))
    flash("Incorrect password","err")
    return redirect(url_for('login'))

@app.route("/forgot_password",methods=['GET','POST'])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")
    email = request.form.get("email","").strip().lower()
    record = readUserRecordbyEmail({'email':email})
    if record is False:
        return render_template("forgot_password.html",
                               err="Database connection failed")
    if record == "No Record":
        return render_template("forgot_password.html",
                               err="Enter a Valid email")
    token = resetPasswordTokenGenerate(email=email)
    reset_url = url_for('reset_password',token=token,_external=True)
    email_status = SendEmail(
        subject = "Reset Password - SNS",
        to_email=email,
        body = emailTemplates.send_reset_password_template(
            user_name=record['name'],
            url=reset_url,
            time=RESET_VALID_SECONDS//60))
    if email_status:
        return render_template("forgot_password.html",
                               msg="Email has been sent")
    return render_template("forgot_password.html",
                           err="Unable to send email")

@app.route('/reset-password/<string:token>',methods=['GET','POST'])
def reset_password(token):
    token_status= validateToken(token=token)
    if token_status=="Invalid":
        return render_template('forgot_password.html',err="Invalid URL")
    elif token_status=="Timeout":
        return render_template('forgot_password.html',err="URL Expired")
    email = token_status
    if request.method == "GET":
        return render_template('reset_password.html',token=token)
    new_password = request.form.get('new_password','')
    confirm_password = request.form.get('confirm_password','')
    if len(new_password)<5:
        return render_template('reset_password.html',token=token,
                               error="Password must be at least 5 characters")
    if new_password != confirm_password:
        return render_template('reset_password.html',token=token,
                               error="Password mismatch")
    update = updatePasswordByIdorEmail({
        'email':email,'new_password':generateHash(new_password)})
    if update:
        flash("Password updated. Please login.","msg")
        return redirect(url_for('login'))
    return render_template('reset_password.html',token=token,
                           error="Could not update the password")

@app.route("/logout",methods=['GET'])
def logout():
    session.clear()
    flash("You have been logged out","msg")
    return redirect(url_for('login'))

#-------------------------------------------------
#   Dashboard / profile
#-------------------------------------------------
#total notes count
#total files count
def getFilesAndNotesCount(user_id):
    try:
        connection = getConnectionWithDB()
        if connection == "Connection Failed":
            return False,"Database Connection Failed"
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM notes WHERE user_id = %s",
                       (user_id,))
        notes_count=cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM file_data WHERE user_id=%s",
                       (user_id,))
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
        cursor= connection.cursor(dictionary=True)
        cursor.execute("""SELECT * FROM notes WHERE user_id=%s
                          ORDER BY updated_at DESC LIMIT 3""",(user_id,))
        recent_notes = cursor.fetchall()
        cursor.close()
        connection.close()
        return True,recent_notes
    except Exception as e:
        return False,f"Exception raised in recent notes:{e}"

@app.route('/dashboard')
@login_required
def dashboard():
    userid = session['id']
    notes_count,files_count = getFilesAndNotesCount(userid)
    if notes_count is False:          # error -> files_count holds message
        flash(files_count,"err")
        notes_count = files_count = 0
    ok,recent_notes = recentNotes(userid)
    if not ok:
        flash(recent_notes,"err")
        recent_notes = []
    return render_template('dashboard.html',
                           username=session['name'],
                           total_notes = notes_count,
                           total_files=files_count,
                           notes=recent_notes)

@app.route('/user/profile',methods=['GET'])
@login_required
def profile():
    return render_template("profile.html",
                           email=session['email'],
                           name=session['name'])

#----------------------------
#       Notes Routes
#-----------------------------
def getNotesByUserId(user_id,filename=None):
    try:
        connection = getConnectionWithDB()
        if connection == "Connection Failed":
            return False,"Database connection Failed"
        cursor = connection.cursor(dictionary=True)
        query = "select * from notes where user_id=%s"
        values = [user_id]
        if filename:
            query +=" and title LIKE %s"
            values.append("%" + filename + "%")
        query += " order by updated_at desc"
        cursor.execute(query,tuple(values))
        notes = cursor.fetchall()
        cursor.close()
        connection.close()
        return True,notes
    except Exception as e:
        return False,f'Exception raised in get notes:{e}'

@app.route('/notes',methods=['GET','POST'])
@login_required
def mynotes():
    search = ""
    if request.method == "POST":
        search = request.form.get('searchnotes','').strip()
    status,notes = getNotesByUserId(user_id=session['id'],
                                    filename=search or None)
    if status:
        return render_template("notes.html",notes=notes,search=search)
    return render_template('notes.html',err=notes)

#insert notes records in table
def addNotesRecord(user_id:int,title:str,content:str):
    try:
        connection = getConnectionWithDB()
        if connection == "Connection Failed":
            return False,"Database Connection Failed"
        cursor = connection.cursor()
        cursor.execute("""INSERT INTO notes(user_id,title,content)
                          values(%s,%s,%s)""",(user_id,title,content))
        connection.commit()
        cursor.close()
        connection.close()
        return True,"Notes Saved"
    except Exception as e:
        return False,f'Exception raised in add notes:{e}'

@app.route('/notes/addnotes',methods=['GET','POST'])
@login_required
def add_notes():
    if request.method == "GET":
        return render_template('addnotes.html')
    title = request.form.get('Title',"").strip() or "No Title"
    content = request.form.get('content',"").strip()
    if not content:
        flash("Content cannot be empty","err")
        return redirect(url_for('add_notes'))
    status,msg = addNotesRecord(user_id=session['id'],
                                title=title,content=content)
    flash(msg,"msg" if status else "err")
    return redirect(url_for('mynotes'))

#get one note - only if it belongs to this user
def getNotesById(notes_id,user_id):
    try:
        connection = getConnectionWithDB()
        if connection == "Connection Failed":
            return False,"Database Connection Failed"
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""select title,content from notes
                          where id=%s and user_id=%s""",(notes_id,user_id))
        notes = cursor.fetchone()
        cursor.close()
        connection.close()
        return True,notes
    except Exception as e:
        return False,f'Exception raised in View Notes:{e}'

@app.route('/notes/view/<int:note_id>')
@login_required
def view_notes(note_id):
    status,notes = getNotesById(note_id,session['id'])
    if not status:
        flash(notes,"err")
        return redirect(url_for('mynotes'))
    if notes is None:
        flash("Note not found","err")
        return redirect(url_for('mynotes'))
    return render_template('viewnotes.html',title=notes['title'],
                           content=notes['content'])

def updateNotesByID(notes_id:int,user_id:int,title:str,content:str):
    try:
        connection = getConnectionWithDB()
        if connection == "Connection Failed":
            return False,"Database Connection Failed"
        cursor= connection.cursor()
        cursor.execute("""update notes set title=%s,content=%s
                          where id=%s and user_id=%s""",
                       (title,content,notes_id,user_id))
        connection.commit()
        cursor.close()
        connection.close()
        return True,"Notes Updated"
    except Exception as e:
        return False,f"Exception raised in update notes:{e}"

@app.route('/notes/edit/<int:note_id>',methods=['GET','POST'])
@login_required
def edit_notes(note_id):
    if request.method == "GET":
        status,notes=getNotesById(note_id,session['id'])
        if status and notes:
            return render_template('updatenotes.html',
                                   title=notes['title'],
                                   content=notes['content'],
                                   notes_id=note_id)
        flash(notes if not status else "Note not found","err")
        return redirect(url_for('mynotes'))
    #POST - first make sure the note really belongs to this user
    #(we don't use rowcount for this: MySQL reports 0 rows when you save
    # without changing anything, which would look like "not found")
    status,existing = getNotesById(note_id,session['id'])
    if not status or existing is None:
        flash(existing if not status else "Note not found","err")
        return redirect(url_for('mynotes'))
    title = request.form.get('title','').strip() or "No Title"
    content = request.form.get('content','').strip()
    status,msg = updateNotesByID(notes_id=note_id,user_id=session['id'],
                                 title=title,content=content)
    flash(msg,"msg" if status else "err")
    return redirect(url_for('mynotes'))

def deleteNotesById(notes_id,user_id):
    try:
        connection = getConnectionWithDB()
        if connection == "Connection Failed":
            return False,"Database Connection Failed"
        cursor = connection.cursor()
        cursor.execute("delete from notes where id=%s and user_id=%s",
                       (notes_id,user_id))
        connection.commit()
        changed = cursor.rowcount
        cursor.close()
        connection.close()
        if changed == 0:
            return False,"Note not found"
        return True,"Notes Deleted"
    except Exception as e:
        return False,f'Exception raised in delete notes:{e}'

#delete is POST only (a GET link can be triggered by accident / by
#other sites); the Delete button in notes.html is a small form.
@app.route('/notes/delete/<int:note_id>',methods=['POST'])
@login_required
def delete_notes(note_id):
    status,msg = deleteNotesById(note_id,session['id'])
    flash(msg,"msg" if status else "err")
    return redirect(url_for('mynotes'))

#------------------------------
#           FILES
#-----------------------------
def getFileIdColumn(cursor):
    """
    Detect whether file_data uses `id` or `file_id` as its primary key.
    The template and routes use the normalized name `id`.
    """
    cursor.execute("SHOW COLUMNS FROM file_data")
    columns = {row[0] for row in cursor.fetchall()}

    if "id" in columns:
        return "id"
    if "file_id" in columns:
        return "file_id"

    raise RuntimeError(
        "The file_data table must contain an `id` or `file_id` column."
    )


def GetFilesbyUserId(userid, filename=None):
    connection = getConnectionWithDB()

    if connection == "Connection Failed":
        return False, "Database Connection Failed"

    cursor = None
    try:
        cursor = connection.cursor(dictionary=True)
        id_column = getFileIdColumn(cursor)

        query = (
            f"SELECT *, {id_column} AS id "
            "FROM file_data WHERE user_id = %s"
        )
        values = [userid]

        if filename:
            query += " AND (stored_name LIKE %s OR original_name LIKE %s)"
            search_value = "%" + filename + "%"
            values.extend([search_value, search_value])

        query += " ORDER BY id DESC"
        cursor.execute(query, tuple(values))
        files = cursor.fetchall()

        # Ensure files.html can consistently use file.id.
        for file_record in files:
            file_record["id"] = file_record.get("id")
            file_record["file_id"] = file_record["id"]

        return True, files

    except Exception as e:
        print("GetFilesbyUserId error:", e)
        return False, f"Exception raised in Search Files: {e}"

    finally:
        if cursor:
            cursor.close()
        connection.close()


@app.route('/files', methods=['GET', 'POST'])
@login_required
def myfiles():
    search = ""

    if request.method == "POST":
        search = request.form.get('searchfiles', '').strip()

    status, files = GetFilesbyUserId(
        userid=session['id'],
        filename=search or None
    )

    if status:
        return render_template('files.html', files=files, search=search)

    flash(files, "err")
    return render_template('files.html', files=[], search=search)


#check file exist in allowed types
ALLOWED_TYPES = {'pdf','doc','docx','jpeg','jpg','png','svg','csv',
                 'xml','txt','py','xlsx','pptx'}
def checkFileAllowed(filename):
    #rsplit -> use the LAST dot, so "my.notes.pdf" works
    return "." in filename and \
           filename.rsplit('.',1)[1].lower() in ALLOWED_TYPES

#check duplicate file
def checkFileDuplicate(userid,filename):
    try:
        connection = getConnectionWithDB()
        if connection == "Connection Failed":
            return False,"Database Connection Failed"
        cursor = connection.cursor()
        cursor.execute("""select id from file_data
                          where stored_name = %s and user_id=%s""",
                       (filename,userid))
        record = cursor.fetchone()
        cursor.close()
        connection.close()
        if record:
            return False,"Duplicate file is present"
        return True, "Not a Duplicate file"
    except Exception as e:
        return False,f"Exception raised in file: {e}"

#insert files into table
def UploadFileInDB(userid,filename,stored_name,type,size,path):
    try:
        connection = getConnectionWithDB()
        if connection == "Connection Failed":
            return False,"Database Connection Failed"
        cursor = connection.cursor()
        cursor.execute("""insert into file_data
                        (user_id,original_name,stored_name,mime_type,
                         size_bytes,storage_path)
                         values(%s,%s,%s,%s,%s,%s)""",
                       (userid,filename,stored_name,type,size,path))
        connection.commit()
        cursor.close()
        connection.close()
        return True,"File Uploaded"
    except Exception as e:
        return False,f'Exception raised in File upload:{e}'

@app.route('/files/upload',methods=['GET','POST'])
@login_required
def uploadFile():
    if request.method == "GET":
        return render_template('uploadFile.html')
    file = request.files.get('file')
    if not file or file.filename == "":
        flash("File not uploaded","err")
        return redirect(url_for('myfiles'))
    filename = file.filename
    if not checkFileAllowed(filename):
        flash("File type not allowed","err")
        return redirect(url_for('myfiles'))
    filename_secure=secure_filename(filename)
    if not checkFileAllowed(filename_secure):   #secure_filename can
        flash("Invalid file name","err")        #strip a whole name
        return redirect(url_for('myfiles'))
    status,msg = checkFileDuplicate(userid=session['id'],
                                    filename=filename_secure)
    if not status:
        flash(msg,"err")
        return redirect(url_for('myfiles'))
    upload_path = os.path.join(UPLOAD_FOLDER,filename_secure)
    file.save(upload_path)
    file_size = os.path.getsize(upload_path)
    file_type = os.path.splitext(filename_secure)[1].lower().lstrip('.')
    status,msg = UploadFileInDB(userid=session['id'],
                                filename=filename,
                                stored_name=filename_secure,
                                type=file_type,
                                size=file_size,
                                path=f'/upload/{filename_secure}')
    flash(msg,"msg" if status else "err")
    return redirect(url_for('myfiles'))

#get file metadata - only if it belongs to this user
def getFileByFileId(fileid, userid):
    connection = getConnectionWithDB()

    if connection == "Connection Failed":
        return False, "Database Connection Failed"

    cursor = None
    try:
        cursor = connection.cursor(dictionary=True)
        id_column = getFileIdColumn(cursor)

        cursor.execute(
            f"SELECT *, {id_column} AS id FROM file_data "
            f"WHERE {id_column} = %s AND user_id = %s",
            (fileid, userid)
        )
        file_record = cursor.fetchone()

        if file_record:
            file_record["id"] = file_record.get("id")
            file_record["file_id"] = file_record["id"]

        return True, file_record

    except Exception as e:
        print("getFileByFileId error:", e)
        return False, f"Exception raised in View File: {e}"

    finally:
        if cursor:
            cursor.close()
        connection.close()


def deleteFileByFileId(fileid, userid):
    """Delete the file row and remove its disk copy when no row uses it."""
    status, file_record = getFileByFileId(fileid, userid)

    if not status:
        return False, file_record
    if file_record is None:
        return False, "File not found"

    connection = getConnectionWithDB()
    if connection == "Connection Failed":
        return False, "Database Connection Failed"

    cursor = None
    try:
        cursor = connection.cursor()
        id_column = getFileIdColumn(cursor)

        cursor.execute(
            f"DELETE FROM file_data WHERE {id_column} = %s AND user_id = %s",
            (fileid, userid)
        )
        connection.commit()

        cursor.execute(
            "SELECT COUNT(*) FROM file_data WHERE stored_name = %s",
            (file_record["stored_name"],)
        )
        still_used = cursor.fetchone()[0]

        if not still_used:
            path = os.path.join(UPLOAD_FOLDER, file_record["stored_name"])
            if os.path.isfile(path):
                os.remove(path)

        return True, "File Deleted Successfully"

    except Exception as e:
        connection.rollback()
        print("deleteFileByFileId error:", e)
        return False, f"Exception raised in Delete File: {e}"

    finally:
        if cursor:
            cursor.close()
        connection.close()


def _send_user_file(file_id,as_attachment):
    status,file = getFileByFileId(file_id,session['id'])
    if not status:
        flash(file,'err')
        return redirect(url_for('myfiles'))
    if file is None:
        flash("File not found","err")
        return redirect(url_for('myfiles'))
    stored = file['stored_name']
    path = os.path.join(UPLOAD_FOLDER,stored)
    if not os.path.isfile(path):
        flash("File is missing on the server","err")
        return redirect(url_for('myfiles'))
    mime_type,_ = mimetypes.guess_type(stored)
    return send_file(path,mimetype=mime_type,as_attachment=as_attachment,
                     download_name=file['original_name'])

@app.route('/files/view/<int:file_id>')
@login_required
def viewFile(file_id):
    return _send_user_file(file_id,as_attachment=False)

@app.route('/files/download/<int:file_id>')
@login_required
def downloadFile(file_id):
    return _send_user_file(file_id,as_attachment=True)

@app.route('/files/delete/<int:file_id>',methods=['POST'])
@login_required
def deleteFile(file_id):
    status,msg = deleteFileByFileId(file_id,session['id'])
    flash(msg,"msg" if status else "err")
    return redirect(url_for('myfiles'))

if (__name__ == "__main__"):
    #debug=True is only for development. Never deploy with it on.
    app.run(host="127.0.0.1",port = 5003,debug=True)

#Registration Flow:
#User --> register.html <--> Registration Form -->
# POST <-->Python  -->Collecting Data -->Validating ->
# Verifying -->Password to Password Hash <-->MYSQL Table
#
#Click Get Started -> Register page -> Name,Email,Password,Confirm
#-> duplicate check -> generate OTP -> email it -> verify page
#-> OTP matches the one in the session (and is < 3 min old)
#-> is_verified = True -> redirect to login
