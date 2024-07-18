from application import app, db
from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
import pytz
from .models import User, Exerciselist, Workout, Exercise, Set

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/workout_log')
@login_required
def workout_log():
    workouts = Workout.query.filter_by(user_id=current_user.id).order_by(Workout.date.desc()).all()
    return render_template('workout_log.html', workouts=workouts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.is_admin:
                flash("Admin olarak giriş yapıldı!", category="success")
                return redirect(url_for('admin_panel'))
            else:
                flash("Giriş başarılı!", category="success")
                return redirect(url_for('workout_log'))
        else:
            flash("Geçersiz kullanıcı adı veya şifre! Lütfen tekrar deneyin.", category="danger")
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        username = request.form['username']
        unhashed_password = request.form['password']

        user_username = User.query.filter_by(username=username).first()

        if user_username:
            flash("Kullanıcı Adı Zaten Kullanılıyor!", category="danger")
            return redirect(url_for('register'))

        user = User(
            firstname=firstname,
            lastname=lastname,
            username=username, 
            password=generate_password_hash(unhashed_password) 
        )
        db.session.add(user)
        db.session.commit()
        flash("Kayıt Başarılı!", category="success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Çıkış Yaptın!", category="warning")
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

@app.route('/trigger-404')
def trigger_404():
    return render_template('nonexistent.html')

@app.route('/trigger-500')
def trigger_500():
    raise Exception("Bu, 500 hata sayfasını test etmek için kasıtlı bir hata.")

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash("Bu sayfaya erişim yetkiniz yok!", category="danger")
        return redirect(url_for('index'))
    
    users = User.query.order_by(User.username).all()
    workouts = Workout.query.order_by(Workout.date.desc()).all()
    return render_template('admin_panel.html', users=users, workouts=workouts, )

@app.route('/admin/add_user', methods=['POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        return jsonify(success=False, message="Bu işlemi yapmaya yetkiniz yok!"), 403
    
    username = request.form['username']
    firstname = request.form['firstname']
    lastname = request.form['lastname']
    password = request.form['password']
    is_admin = 'is_admin' in request.form
    
    user = User(
        username=username,
        firstname=firstname,
        lastname=lastname,
        password=generate_password_hash(password), 
        is_admin=is_admin
    )
    db.session.add(user)
    db.session.commit()
    return jsonify(success=True, message="Yeni kullanıcı eklendi!")

@app.route('/admin/edit_user/<int:user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        return jsonify(success=False, message="Bu işlemi yapmaya yetkiniz yok!"), 403
    
    user = User.query.get_or_404(user_id)
    
    user.username = request.form['username']
    user.firstname = request.form['firstname']
    user.lastname = request.form['lastname']
    
    if request.form.get('password'):
        user.password = generate_password_hash(request.form['password'])
    
    user.is_admin = 'is_admin' in request.form
    db.session.commit()
    return jsonify(success=True, message="Kullanıcı güncellendi!")

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return jsonify(success=False, message="Bu işlemi yapmaya yetkiniz yok!"), 403
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify(success=True, message="Kullanıcı silindi!")

@app.route('/admin/get_user/<int:user_id>')
@login_required
def get_user(user_id):
    if not current_user.is_admin:
        return jsonify(success=False, message="Yetkisiz erişim"), 403
    user = User.query.get_or_404(user_id)
    return jsonify(id=user.id, username=user.username, firstname=user.firstname, lastname=user.lastname)

@app.route('/trainers')
def trainers():
    return render_template('trainers.html')