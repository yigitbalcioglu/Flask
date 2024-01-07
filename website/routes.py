from .extensions import db
from flask import render_template, redirect, url_for, flash, request,Blueprint,jsonify,make_response,session
import flask
from .models import User,Event,Session,FilePath
from flask_login import current_user,login_required
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta,date
from dateutil.rrule import rrule, MONTHLY, YEARLY, DAILY,HOURLY
from flask_uploads import UploadSet, configure_uploads, ALL
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
import matplotlib.pyplot as plt
import os
import requests
import google.oauth2.credentials
import google_auth_oauthlib.flow

#routesa initten app geliyor 
main=Blueprint("main", __name__)

CLIENT_SECRETS_FILE = "website/client_secret.json"
SCOPES = ['https://www.googleapis.com/auth/calendar',
          'https://www.googleapis.com/auth/calendar.events.owned']



@main.route('/')
@main.route('/home')
def home_page(user_id):
    render_template('home.html')

@main.route('/register', methods=['POST'])
def register_page():

    data = request.get_json()
    unique_id=str(uuid.uuid4())
    if not data:
        return make_response("invalid content type",415)
    
    if User.query.filter_by(username=data["username"]).first():
        return jsonify(message="Bu kullanıcı adı zaten kullanılıyor."),409
    
    
    if User.query.filter_by(email_address=data["email"]).first():
        return jsonify(message="Bu email zaten kullanılıyor."),409
    
    hashed_password=generate_password_hash(data["password"])
    
    user_to_create = User(id=unique_id,
                          username=data['username'],
                          email_address=data['email'],
                          password_hash=hashed_password)  # Burada şifre hash'lenmelidir
     # Kullanıcıyı veritabanına ekle
    
    try:
        db.session.add(user_to_create)
        db.session.commit()
        return jsonify({"Message":"Success"}),200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Kullanıcı kaydedilemedi.', 'error': str(e)}), 500
    # Başarılı kayıt için JSON cevabı döndür

@main.route('/login', methods=['GET', 'POST'])
def login_page():
    data=request.get_json()
    
    if not data:
        return make_response("invalid content type",415)
    
    user=User.query.filter_by(username=data["username"]).first()
    #kullanıcı adı bulunduysa
 
    if (user):    
        if check_password_hash(user.password_hash,data["password"]):
            session=create_session(user.id)
            return jsonify({"Message":"Success", "session_id":session.session_id})
        else:
            return jsonify(message="Şifreler uyuşmuyor"),406
    else:
        return jsonify(message="Başarısız"), 405
    
def create_session(user_id):
    new_session = Session(
        session_id=str(uuid.uuid4()),
        user_id=user_id,
        expires_at=datetime.utcnow() + timedelta(minutes=30)
    )
    db.session.add(new_session)
    db.session.commit()
    return new_session

def delete_session(user_id):
    sessions=Session.query.filter_by(user_id=user_id).all()
    for session in sessions:
         db.session.delete(session)
    db.session.commit
    
    
def check_session_active(session_id):
    session = Session.query.get(session_id)
    if session and session.is_active:
        return True
    return False

#@login_required
@main.route('/api/create_event', methods=['POST'])
def create_event():
    data = request.get_json()
    #title date owner id
    unique_id=str(uuid.uuid4())
    data["category"]= str(data["category"]).lower()
    categories=["hobby", "study", "sports", "chores","miscellaneous"]
    
   
    #recurrence_type=data["recurrence_type"],
                      #recurrence_start_date=data["recurrence_start_date"],
                      #recurrence_end_date=data["recurrence_end_date"])
    if data["category"] not in categories:
        return jsonify("Category is not valid!"),201
    else:
        new_event = Event(id=unique_id,
                      title=data['title'], 
                      date=data['date'],
                      start_time=data["start_time"],
                      end_time=data["end_time"],
                      category=data["category"])
                      
        db.session.add(new_event)
        db.session.commit()
        return jsonify({'message': 'new event created'}), 200
        
    


@main.route('/api/get_day_events', methods=['GET'])
def get_day_events():
    events = Event.query.filter_by(title="deneme123").all()
    
    return jsonify([{
        'title': event.title,
        'start_time': event.start_time.strftime('%H:%M:%S') if event.start_time else None,
        'end_time': event.end_time.strftime('%H:%M:%S') if event.end_time else None,
        'date': event.date.strftime('%Y-%m-%d') if event.date else None
    } for event in events])
    
#burak'ın kodları
@main.route('/delete_event/<id>', methods=['DELETE'])
def delete_event(id):
    #find the event to delete by its id
    event_to_delete = Event.query.get(id)
    if not event_to_delete:
        return jsonify({'error': 'Event not found'}), #hata kodeu girilecek
    #delete it from database
    db.session.delete(event_to_delete)
    db.session.commit()
    #return confirmation message
    return jsonify({'message': 'Event deleted.'}), 202


@main.route('/update_event/<id>', methods=['PUT'])
def update_event(id):
    data = request.get_json()
    #find the event to update by its id
    event_to_update = Event.query.get(id)
    if not event_to_update:
        return jsonify({'error': 'Event not found'}), #hata kodu girilecek
    #update the event (title, date)
    event_to_update.title = data.get('title', event_to_update.title)
    event_to_update.date = data.get('date', event_to_update.date)
    db.session.commit()
    return jsonify({'message': 'Event updated.'}), 203

@main.route('/add_file_to_event/<id>', methods=['PUT'])
def add_file_to_event(id):
    event_to_add_file = Event.query.get(id)

    if not event_to_add_file:
        return jsonify({'error': 'Event not found'}), 404
    
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join('uploads', filename)
        file.save(file_path)
        event_to_add_file.file_path = file_path 
        db.session.commit()

        file_path_id = str(uuid.uuid4())
        
        file_path_obj = FilePath(id=file_path_id, path=file_path, event_id=event_to_add_file.id)
        db.session.add(file_path_obj)
        db.session.commit()
        return jsonify({'message': 'File uploaded successfully', 'filename': filename}), 204
    else:
        return jsonify({'error': 'Invalid or missing file'}), 406

def allowed_file(filename):
    allowed_extensions = {'jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'txt'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

@main.route('/delete_file_from_event/<event_id>/<file_path_id>', methods=['DELETE'])
def delete_file_from_event(event_id, file_path_id):
    event_to_delete_file = Event.query.get(event_id)
    
    if not event_to_delete_file:
        return jsonify({'error': 'Event not found'}), 404

    file_path_obj = FilePath.query.get(file_path_id)

    if not file_path_obj or file_path_obj.event_id != event_to_delete_file.id:
        return jsonify({'error': 'File path not found for the event'}), 404

    db.session.delete(file_path_obj)
    os.remove(file_path_obj.path)
    db.session.commit()

    return jsonify({'message': 'File deleted successfully'}), 204


@main.route('/api/events/summary', methods=['GET'])
def show_summary():
    data = request.get_json()
    year = data["year"]
    month = data["month"]
    day = data["day"]
    d = date(int(year),int(month), int(day))
    categories = {
        "hobby": 0, 
        "study": 0,
        "sports": 0,
        "chores": 0,
        "miscellaneous": 0
    }
    
    time_period = data["time_period"]
    if time_period == 1:
        
        if not (Event.query.filter_by(date=d).all()):
            return jsonify({'message': 'no events available'})
        else:
            for event in Event.query.filter_by(date=d).all():
                duration = float(event.duration)
                categories[event.category] += duration
            plt.pie(values, labels=labels, autopct='%1.1f%%')
            plt.show() 
        
    elif time_period == 2 :
        week = d.strftime("%W")
        for event in Event.query.all():
            if event.date.strftime("%Y") == year and event.date.strftime("%W") == week:
                duration = float(event.duration)
                categories[event.category] += duration
        labels = list(categories.keys())
        values = list(categories.values())
        if values.count(0) == 5:
            return jsonify({'message': 'no events available'})
        else:
            plt.pie(values, labels=labels, autopct='%1.1f%%')
            plt.show()
                     
                   
    elif time_period == 3 :
        for event in Event.query.all():
            if event.date.strftime("%m") == month and event.date.strftime("%Y") == year:
                duration = float(event.duration)
                categories[event.category] += duration
        labels = list(categories.keys())
        values = list(categories.values())
        if values.count(0) == 5:
            return jsonify({'message': 'no events available'})
        else:
            plt.pie(values, labels=labels, autopct='%1.1f%%')
            plt.show()
            
    elif time_period == 4 :
        for event in Event.query.all():
            if event.date.strftime("%Y") == year:     
                duration = float(event.duration)
                categories[event.category] += duration
        labels = list(categories.keys())
        values = list(categories.values())
        if values.count(0) == 5:
            return jsonify({'message': 'no events available'})
        else:
            plt.pie(values, labels=labels, autopct='%1.1f%%')
            plt.show() 
    
    else:
        return jsonify({'message': 'invalid number of time period'})

    return jsonify({'message': 'summary has showed'})

@main.route('/friends/<user>', methods=['PUT', 'GET', 'DELETE'])
def friends(user):
    active_user = User.query.filter_by(username=user).first()
    data = request.get_json()

    if request.method == 'PUT':
        if User.query.filter_by(username=data["friend"]).first():
            active_user.friends += " " + data["friend"]
            db.session.commit()
            return jsonify({'message': f'{data["friend"]} added as a friend'}), 200
        else:
            return jsonify({'message': 'user can not be found'}), 201

    if request.method == 'GET':
        if not data["friend"]:
            return jsonify({'message': f'{active_user.friends}'}), 200
        elif active_user.username in User.query.filter_by(username=data["friend"]).first().friends.split():
            return Event.query.filter_by(owner=data["friend"], access_level="public").all()
        else:
            return jsonify({'message': f'You can not access to events of {data["friend"]}'})

    if request.method == 'DELETE':
        friends_list = active_user.friends.split()
        if data["friend"] in friends_list:
            friends_list = set(friends_list)
            friends_list.discard(data["friend"])
            friends_list = list(friends_list)
            active_user.friends = " ".join(friends_list)
            db.session.commit()
            return jsonify({'message': f'{data["friend"]} is no longer your friend.'}), 200
        else:
            return jsonify({'message': f'{data["friend"]} is not in your friends list.'}), 201

@main.route("/authorize")
def oauth2():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    flow.redirect_uri = flask.url_for('main.oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
      access_type='offline',
      include_granted_scopes='true')

    flask.session['state'] = state

    return flask.redirect(authorization_url) 
        
@main.route("/credentials")
def credentials():
    if flask.session["credentials"]:
        return flask.jsonify(flask.session["credentials"])

@main.route('/revoke')
def revoke():
    if 'credentials' not in flask.session:
        return ('You need to <a href="/authorize">authorize</a> before ' +
                'testing the code to revoke credentials.')

    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    revoke = requests.post('https://oauth2.googleapis.com/revoke',
                           params={'token': credentials.token},
                           headers = {'content-type': 'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        return 'Credentials successfully revoked.'
    else:
        return 'An error occurred.'
            
@main.route('/clear')
def clear_credentials():
    if 'credentials' in flask.session:
        del flask.session['credentials']
        return "Credentials cleared"


@main.route("/oauth2callback")
def oauth2callback():
    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = flask.url_for('main.oauth2callback', _external=True)

    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials
    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.redirect(flask.url_for('home'))


def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}


@login_required
@main.route('/logout')
def logout_page():
    delete_session(current_user.user_id)
    flash("You have been logged out!", category='info')
    return redirect(url_for("home_page"))









