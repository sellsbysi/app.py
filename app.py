from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, JWTManager
import datetime

app = Flask(__name__)

# Configuración de la base de datos
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["JWT_SECRET_KEY"] = "clave_secreta_super_segura"

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Modelo de usuario
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    instagram_username = db.Column(db.String(50), nullable=True)
    instagram_password = db.Column(db.String(200), nullable=True)

# Ruta para registrar usuarios
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data["password"]).decode("utf-8")
    new_user = User(username=data["username"], email=data["email"], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Usuario registrado exitosamente"}), 201

# Ruta para iniciar sesión
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data["email"]).first()

    if user and bcrypt.check_password_hash(user.password, data["password"]):
        access_token = create_access_token(identity=user.id, expires_delta=datetime.timedelta(days=1))
        return jsonify({"token": access_token, "message": "Inicio de sesión exitoso"})
    else:
        return jsonify({"message": "Credenciales incorrectas"}), 401

# Ruta para conectar cuenta de Instagram
@app.route("/connect_instagram", methods=["POST"])
@jwt_required()
def connect_instagram():
    data = request.get_json()
    user = User.query.filter_by(id=get_jwt_identity()).first()
    
    if user:
        user.instagram_username = data["instagram_username"]
        user.instagram_password = bcrypt.generate_password_hash(data["instagram_password"]).decode("utf-8")
        db.session.commit()
        return jsonify({"message": "Cuenta de Instagram vinculada correctamente"})
    else:
        return jsonify({"message": "Usuario no encontrado"}), 404

# Inicializar base de datos
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
