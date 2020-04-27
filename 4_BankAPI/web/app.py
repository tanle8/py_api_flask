from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongo://db:27017")
db = client.BankAPI
users = db["Users"]


def UserExist(username):
    if users.find({"Username": username}).count() == 0:
        return False
    else:
        return True


def genReturnDictionary(status, msg):
    retJson = {
        "status": status,
        "msg": msg
    }
    return retJson


def verifyPw(username, password):
    if not UserExist(username):
        return False

    hashed_pw = users.find({
        "Username": username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf-8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False


def verifyCredentials(username, password):
    if not UserExist(username):
        return genReturnDictionary(301, "Invalid Username"), True

    correct_pw = verifyPw(username, password)

    if not correct_pw:
        return genReturnDictionary(302, "Incorrect Password"), True

    return None, False


def cashWithUser(username):
    cash = users.find({
        "Username":username
    })[0]["Own"]
    return cash


def debtWithUser(username):
    debt = users.find({
        "Username": username
    })[0]["Debt"]
    return debt


def updateAccount(username, balance):
    users.update({
        "Username": username
    }, {
        "$set": {
            "Own": balance
        }
    })


def updateDebt(username, balance):
    users.update({
        "Username": username,
    }, {
        "$set": {
            "Debt": balance
        }
    })


class Register(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        if UserExist(username):
            return jsonify(genReturnDictionary(301, "Invalid Username"))

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        users.insert({
            "Username": username,
            "Password": hashed_pw,
            "Own": 0,
            "Debt": 0
        })

        return jsonify(genReturnDictionary(200, "You successfully signed up for the API"))


class Add(Resource):

    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        money = postedData["amount"]

        retJson, error = verifyCredentials(username, password)

        if error:
            return jsonify(retJson)

        if money <= 0:
            return jsonify(genReturnDictionary(304, "The money amount entered must be > 0"))

        cash = cashWithUser(username)
        # Take 1 as a fee and Add to bank's number
        money -= 1
        bank_cash = cashWithUser("BANK")
        updateAccount("BANK", bank_cash+1)
        updateAccount(username, cash + money)

        return jsonify(genReturnDictionary(200, "Amount added successfully to account"))


class Transfer(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        rec