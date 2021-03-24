from flask import Flask
from flask import jsonify
from flask import request

from datetime import timedelta
from time import strftime

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

import csv

app = Flask(__name__)

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "SECRET_KEY"  # Change this!
# after timedelta(XXX) JWT will no longer be valid, even the signature is correct and everything is matched.
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
jwt = JWTManager(app)


api_password = "api_password"
db_password = "db_password"


def get_time():
    time = strftime("%Y-%m-%dT%H:%M:%S")
    return time


def save_test_logs(info, username, password, ip):
    data = open('test_error.log', 'a')
    timestamp = get_time()
    data.write('{}, {}, {}, {}, {}\n'.format(timestamp, info, username, password, ip))
    data.close()


def save_api_logs(info, username, password, ip):
    data = open('api_error.log', 'a')
    timestamp = get_time()
    data.write('{}, {}, {}, {}, {}\n'.format(timestamp, info, username, password, ip))
    data.close()


def save_db_logs(info, username, password, ip):
    data = open('db_error.log', 'a')
    timestamp = get_time()
    data.write('{}, {}, {}, {}, {}\n'.format(timestamp, info, username, password, ip))
    data.close()


def import_data_from_csv_file():
    csv_user_list = []
    with open('devicesID.csv', newline='') as f:
        reader = csv.reader(f)
        csv_data_list = list(reader)

    for i in range(len(csv_data_list)):
        if i > 0:
            csv_user_list.append(str(csv_data_list[i][1]) + "-" + str(csv_data_list[i][0]))
    # print("csv_user_list: {}".format(csv_user_list))
    return csv_user_list


userList = import_data_from_csv_file()
print("userList: {}".format(userList))


# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.
@app.route("/get_token", methods=["POST"])  # do it every 45 minutes
def get_token():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    if username not in userList or password != "test":
        save_test_logs('login failed', username, password, request.remote_addr)
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=username)
    return jsonify(test_access_token=access_token)


@app.route("/get_api_token", methods=["POST"])
def get_api_token():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    if username not in userList or password != api_password:
        # log username, password and IP!!
        save_api_logs('login failed', username, password, request.remote_addr)
        return jsonify({"msg": "Bad username or password"}), 401

    api_access_token = create_access_token(identity=username)
    return jsonify(api_access_token=api_access_token)


@app.route("/get_db_token", methods=["POST"])
def get_db_token():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    if username not in userList or password != db_password:
        # log username, password and IP!!
        save_db_logs('login failed', username, password, request.remote_addr)
        return jsonify({"msg": "Bad username or password"}), 401

    db_access_token = create_access_token(identity=username)
    return jsonify(db_access_token=db_access_token)


# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@app.route("/protected", methods=["GET"])
@jwt_required
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == "__main__":
    app.run()
