from .extensions import db
from flask import render_template, redirect, url_for, flash, request,Blueprint,jsonify,make_response,session
from .models import User,Event,Session
from flask_login import login_user, logout_user, current_user,login_required
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta



#routesa initten app geliyor 
main=Blueprint("main", __name__)

@main.route('/')
@main.route('/home')
def home_page(user_id):
    render_template('home.html')

@main.route('/register', methods=['GET', 'POST'])
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
        return jsonify({"Message":"Success"})
        
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
        return jsonify(message="Başarısız"), 404
    
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
    #data=request.get_json()
    #date=data["date"]
    #date = datetime.strptime(date, '%Y-%m-%d').date()
    events = Event.query.filter_by(title="deneme123").all()
    
    return jsonify([{
        'title': event.title,
        'start_time': event.start_time.strftime('%H:%M:%S') if event.start_time else None,
        'end_time': event.end_time.strftime('%H:%M:%S') if event.end_time else None,
        'date': event.date.strftime('%Y-%m-%d') if event.date else None
    } for event in events])

            
@login_required
@main.route('/logout')
def logout_page():
    delete_session(current_user.user_id)
    flash("You have been logged out!", category='info')
    return redirect(url_for("home_page"))









