from datetime import datetime
from flask_restful.utils import http_status_message
import redis
import json
import hashlib
from flask import request
from flask_restful import Resource,Api
from flask import Flask
from typing import Dict
from flask import Flask
import random
import string
import requests

from werkzeug.http import HTTP_STATUS_CODES

gestor_seguridad_url = "http://miso-gestorseguridad.herokuapp.com/gestorSeguridad"

redisInstance = redis.Redis(
    host='ec2-50-19-196-205.compute-1.amazonaws.com', 
    port=17830,
    password="p8246bd54e4335f5d4001090409c247e242ebbc0d28a3a9a8f92400e7b9e1d178",
    ssl=True,
    ssl_cert_reqs=None,
    charset="utf-8",
    decode_responses=True
    )

#tabla cobros pendientes
tbl_cobros_pendientes = redisInstance.hgetall("tbl_cobros_pendientes")
#tabla de usuarios
tbl_usuarios=redisInstance.hgetall("tbl_usuario")

def searchByField(collection, searchForCollection, field1, valueToSearch1,field2=None, valueToSearch2=None):
    output=[]
    for value in collection:
        item=json.loads(collection[value])
        if item[field1]==valueToSearch1:
            if field2 is None:
                if searchForCollection==True:
                    output.append(item)
                else:
                    return item
            else:
                if item[field2]==valueToSearch2:
                    if searchForCollection==True:
                        output.append(item)
                    else:
                        return item
            
    if searchForCollection==True:
        return output
    else:
        return None

PREFIX = 'Bearer'

def get_token(header):
    bearer, _, token = header.partition(' ')
    if bearer != PREFIX:
        raise ValueError('Invalid token')

    return token

def validarToken():
    token = get_token(request.headers.get('Authorization'))
    response = requests.post(gestor_seguridad_url+'/authorizeToken', json={"token": token})
    if response.status_code == 200:
        data = response.json()
        return data["id"]
    else: 
        return None

def validarAccion(accion_id, usuario_id):
    response = requests.post(gestor_seguridad_url+'/authorizeAction', json={"usuarioId": usuario_id, "accionId": accion_id})
    if response.status_code == 200:
        data = response.json()
        return bool(data["autorization"])
    else: 
        return False

def firmaHash(contenido, usuarioId):
    toHash=str(usuarioId)+"-"+str(contenido)
    hash_object= hashlib.sha256(toHash.encode())
    return hash_object.hexdigest()

class HealthCheck(Resource):    

    def get(self):
        data={
            "echo" : "ok"
        }
        return data

class Cobros(Resource):
    def get(self, id_paciente):
        usuario_id = validarToken()
        print(str(usuario_id))
        if usuario_id is None:
            return ('Autenticacion no válida', 403)
        autoriza = validarAccion(2001, usuario_id)
        if autoriza == False:
            return ('Usuario no autorizado para realizar esta acción', 403)
        paciente = searchByField(tbl_usuarios,False,"id",id_paciente)
        return {"nombrePaciente": paciente["name"], "emailPaciente" : paciente["email"],"cobrosPendientes" : searchByField(tbl_cobros_pendientes,True,"usuarioId",id_paciente)}


app = Flask(__name__) 
app_context = app.app_context()
app_context.push()


api = Api(app)
api.add_resource(HealthCheck, "caja/healthcheck")
api.add_resource(Cobros, "/caja/paciente/<int:id_paciente>")

if __name__ == '__main__':
    app.run()