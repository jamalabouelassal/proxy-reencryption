from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from umbral import (
    SecretKey, Signer, encrypt, decrypt_reencrypted,
    generate_kfrags, reencrypt, CapsuleFrag, decrypt_original, Capsule
)
from umbral.keys import PublicKey
import os
from datetime import datetime
import random
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    signing_key = db.Column(db.Text, nullable=False)
    verifying_key = db.Column(db.Text, nullable=False)
    messages_sent = db.relationship('Message', backref='author', lazy=True)
    messages_received = db.relationship('MessageRecipient', backref='recipient', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    encrypted_content = db.Column(db.Text, nullable=False)
    capsule = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipients = db.relationship('MessageRecipient', backref='message', lazy=True)

class MessageRecipient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    cfrags = db.Column(db.Text, nullable=False)  # Liste de cfrags sérialisée

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Ce nom d\'utilisateur est déjà pris')
            return redirect(url_for('register'))
        
        # Générer les clés Umbral
        secret_key = SecretKey.random()
        public_key = secret_key.public_key()
        signing_key = SecretKey.random()
        verifying_key = signing_key.public_key()
        
        user = User(
            username=username,
            password=password,
            public_key=bytes(public_key).hex(),
            private_key=bytes(secret_key).hex(),
            signing_key=bytes(signing_key).hex(),
            verifying_key=bytes(verifying_key).hex()
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Compte créé avec succès')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Incorrect username or password')
    # On GET, always redirect to homepage
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    messages = Message.query.filter_by(sender_id=current_user.id).all()
    received_messages = MessageRecipient.query.filter_by(recipient_id=current_user.id).all()
    users = User.query.all()
    return render_template('dashboard.html', messages=messages, received_messages=received_messages, users=users)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    content = request.form['message']
    recipient_ids = request.form.getlist('recipients')

    if not recipient_ids:
        flash('Veuillez sélectionner au moins un destinataire')
        return redirect(url_for('dashboard'))

    # Récupérer les clés de l'expéditeur
    sender_secret_key = SecretKey.from_bytes(bytes.fromhex(current_user.private_key))
    sender_public_key = sender_secret_key.public_key()
    sender_signing_key = SecretKey.from_bytes(bytes.fromhex(current_user.signing_key))
    sender_signer = Signer(sender_signing_key)

    # Chiffrer le message texte
    capsule, ciphertext = encrypt(sender_public_key, content.encode())

    # Créer le message
    message = Message(
        encrypted_content=ciphertext.hex(),
        capsule=bytes(capsule).hex(),
        sender_id=current_user.id
    )
    db.session.add(message)

    # Créer les fragments de re-chiffrement pour chaque destinataire
    for recipient_id in recipient_ids:
        recipient = User.query.get(recipient_id)
        recipient_secret_key = SecretKey.from_bytes(bytes.fromhex(recipient.private_key))
        recipient_public_key = recipient_secret_key.public_key()

        kfrags = generate_kfrags(
            delegating_sk=sender_secret_key,
            receiving_pk=recipient_public_key,
            signer=sender_signer,
            threshold=10,
            num_kfrags=20
        )
        selected_kfrags = random.sample(kfrags, 10)
        cfrags = [reencrypt(capsule, kfrag) for kfrag in selected_kfrags]
        message_recipient = MessageRecipient(
            message=message,
            recipient_id=recipient_id,
            cfrags=','.join([bytes(cfrag).hex() for cfrag in cfrags])
        )
        db.session.add(message_recipient)

    db.session.commit()
    flash('Message envoyé avec succès')
    return redirect(url_for('dashboard'))

@app.route('/decrypt_message/<int:message_id>')
@login_required
def decrypt_message(message_id):
    message = Message.query.get_or_404(message_id)
    message_recipient = MessageRecipient.query.filter_by(
        message_id=message_id,
        recipient_id=current_user.id
    ).first()

    if not message_recipient:
        flash('You are not authorized to read this message')
        return redirect(url_for('dashboard'))

    recipient_secret_key = SecretKey.from_bytes(bytes.fromhex(current_user.private_key))
    sender_secret_key = SecretKey.from_bytes(bytes.fromhex(message.author.private_key))
    sender_public_key = sender_secret_key.public_key()
    sender_verifying_key = PublicKey.from_bytes(bytes.fromhex(message.author.verifying_key))

    capsule = Capsule.from_bytes(bytes.fromhex(message.capsule))
    cfrags_hex = message_recipient.cfrags.split(',')
    cfrags = [CapsuleFrag.from_bytes(bytes.fromhex(cfrag_hex)) for cfrag_hex in cfrags_hex]
    verified_cfrags = [
        cfrag.verify(
            capsule=capsule,
            verifying_pk=sender_verifying_key,
            delegating_pk=sender_public_key,
            receiving_pk=recipient_secret_key.public_key()
        ) for cfrag in cfrags
    ]
    decrypted = decrypt_reencrypted(
        receiving_sk=recipient_secret_key,
        delegating_pk=sender_public_key,
        capsule=capsule,
        verified_cfrags=verified_cfrags,
        ciphertext=bytes.fromhex(message.encrypted_content)
    )
    return render_template('decrypt.html', message=message, decrypted_message=decrypted.decode())

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Vous avez été déconnecté avec succès', 'success')
    return redirect(url_for('index'))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user = current_user
    # Delete received message links
    MessageRecipient.query.filter_by(recipient_id=user.id).delete()
    # Delete sent messages and their recipients
    sent_messages = Message.query.filter_by(sender_id=user.id).all()
    for msg in sent_messages:
        MessageRecipient.query.filter_by(message_id=msg.id).delete()
        db.session.delete(msg)
    # Delete the user
    db.session.delete(user)
    db.session.commit()
    logout_user()
    flash('Your account has been deleted.', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 